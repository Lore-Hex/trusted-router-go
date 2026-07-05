package trustedrouter

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultOAuthLoopbackPort is the fixed desktop loopback port allowlisted by
	// the TrustedRouter backend. Keep the authorize callback origin exactly
	// http://localhost:3000/callback; non-allowlisted loopback origins are
	// rejected by the backend at authorize time.
	DefaultOAuthLoopbackPort = 3000

	defaultOAuthLoopbackPath         = "/callback"
	defaultOAuthLoopbackBindHost     = "127.0.0.1"
	defaultOAuthLoopbackCallbackHost = "localhost"
	oauthLoopbackCloseTimeout        = 2 * time.Second
)

// OAuthLoopbackOptions configures a localhost OAuth loopback listener.
type OAuthLoopbackOptions struct {
	// Port is the local TCP port to bind. Zero uses DefaultOAuthLoopbackPort so
	// the callback URL matches the backend-allowlisted loopback origin exactly.
	Port int
	// EphemeralPort keeps the underlying Port=0 bind available and uses the
	// OS-assigned port in CallbackURL. That remains useful for tests, but the
	// resulting callback origin is not backend-allowlisted and will be rejected
	// by the authorize endpoint.
	EphemeralPort bool
	// Path is the callback path. Empty uses "/callback".
	Path string
	// State is the expected OAuth state. It is equivalent to ExpectedState.
	State string
	// ExpectedState is the expected OAuth state for anti-CSRF validation.
	ExpectedState string
	// SuccessHTML overrides the minimal success page.
	SuccessHTML string
	// DenyHTML overrides the minimal denial page.
	DenyHTML string
}

// OAuthLoopbackResult is the captured OAuth callback.
type OAuthLoopbackResult struct {
	Code  string
	State string
}

// OAuthLoopback is a one-shot localhost OAuth callback listener.
type OAuthLoopback struct {
	listener      net.Listener
	server        *http.Server
	callbackURL   string
	expectedState string
	successHTML   string
	denyHTML      string
	result        chan oauthLoopbackResult
	resultOnce    sync.Once
	closeOnce     sync.Once
}

type oauthLoopbackResult struct {
	value OAuthLoopbackResult
	err   error
}

// StartOAuthLoopback starts a localhost OAuth loopback listener.
func StartOAuthLoopback(opts OAuthLoopbackOptions) (*OAuthLoopback, error) {
	path := opts.Path
	if path == "" {
		path = defaultOAuthLoopbackPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	expectedState := opts.ExpectedState
	if expectedState == "" {
		expectedState = opts.State
	}
	successHTML := opts.SuccessHTML
	if successHTML == "" {
		successHTML = defaultOAuthLoopbackSuccessHTML
	}
	denyHTML := opts.DenyHTML
	if denyHTML == "" {
		denyHTML = defaultOAuthLoopbackDenyHTML
	}

	port := opts.Port
	if opts.EphemeralPort {
		port = 0
	} else if port == 0 {
		port = DefaultOAuthLoopbackPort
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", defaultOAuthLoopbackBindHost, port))
	if err != nil {
		return nil, err
	}
	port = listener.Addr().(*net.TCPAddr).Port
	loopback := &OAuthLoopback{
		listener:      listener,
		callbackURL:   fmt.Sprintf("http://%s:%d%s", defaultOAuthLoopbackCallbackHost, port, path),
		expectedState: expectedState,
		successHTML:   successHTML,
		denyHTML:      denyHTML,
		result:        make(chan oauthLoopbackResult, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, loopback.handleCallback)
	loopback.server = &http.Server{Handler: mux}
	go func() {
		err := loopback.server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			loopback.deliver(oauthLoopbackResult{err: err})
		}
	}()
	return loopback, nil
}

// NewOAuthLoopback starts a localhost OAuth loopback listener.
func NewOAuthLoopback(opts OAuthLoopbackOptions) (*OAuthLoopback, error) {
	return StartOAuthLoopback(opts)
}

// CallbackURL returns the callback URL to include in the authorize request.
func (l *OAuthLoopback) CallbackURL() string {
	if l == nil {
		return ""
	}
	return l.callbackURL
}

// Wait waits for the OAuth callback, validates state, returns code/state, and shuts down the listener.
func (l *OAuthLoopback) Wait(ctx context.Context) (OAuthLoopbackResult, error) {
	if l == nil {
		return OAuthLoopbackResult{}, errors.New("nil OAuthLoopback")
	}
	defer l.Close()
	select {
	case result := <-l.result:
		return result.value, result.err
	case <-ctx.Done():
		return OAuthLoopbackResult{}, ctx.Err()
	}
}

// Close shuts down the loopback listener. It is safe to call multiple times.
func (l *OAuthLoopback) Close() error {
	if l == nil {
		return nil
	}
	var err error
	l.closeOnce.Do(func() {
		if l.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), oauthLoopbackCloseTimeout)
			defer cancel()
			if shutdownErr := l.server.Shutdown(ctx); shutdownErr != nil {
				closeErr := l.server.Close()
				if closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
					err = errors.Join(shutdownErr, closeErr)
				} else if !errors.Is(shutdownErr, http.ErrServerClosed) && !errors.Is(shutdownErr, context.DeadlineExceeded) {
					err = shutdownErr
				}
			}
		} else if l.listener != nil {
			err = l.listener.Close()
		}
	})
	return err
}

func (l *OAuthLoopback) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	if oauthErr := query.Get("error"); oauthErr != "" {
		desc := query.Get("error_description")
		message := "OAuth error: " + oauthErr
		if desc != "" {
			message += " - " + desc
		}
		l.denyAndDeliver(w, message)
		return
	}
	code := query.Get("code")
	if code == "" {
		message := "OAuth callback missing 'code'"
		l.denyAndDeliver(w, message)
		return
	}
	state := query.Get("state")
	if l.expectedState != "" && state != l.expectedState {
		message := "OAuth state mismatch (possible CSRF); aborting exchange"
		l.denyAndDeliver(w, message)
		return
	}
	l.writeSuccess(w)
	l.deliver(oauthLoopbackResult{value: OAuthLoopbackResult{Code: code, State: state}})
}

func (l *OAuthLoopback) deliver(result oauthLoopbackResult) {
	l.resultOnce.Do(func() {
		l.result <- result
	})
}

func (l *OAuthLoopback) writeSuccess(w http.ResponseWriter) {
	writeHTMLResponse(w, http.StatusOK, l.successHTML)
}

func (l *OAuthLoopback) denyAndDeliver(w http.ResponseWriter, message string) {
	l.writeDeny(w, message)
	l.deliver(oauthLoopbackResult{err: errors.New(message)})
}

func (l *OAuthLoopback) writeDeny(w http.ResponseWriter, message string) {
	body := strings.ReplaceAll(l.denyHTML, "{{message}}", html.EscapeString(message))
	writeHTMLResponse(w, http.StatusBadRequest, body)
}

func writeHTMLResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

const defaultOAuthLoopbackSuccessHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Signed in</title></head><body><h1>Signed in with TrustedRouter</h1><p>You can close this tab and return to the app.</p></body></html>`

const defaultOAuthLoopbackDenyHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in failed</title></head><body><h1>TrustedRouter sign in failed</h1><p>{{message}}</p></body></html>`

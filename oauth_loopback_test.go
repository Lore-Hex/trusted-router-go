package trustedrouter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOAuthLoopbackDefaultCallbackURLMatchesBackendAllowlist(t *testing.T) {
	loopback, err := StartOAuthLoopback(OAuthLoopbackOptions{})
	if err != nil {
		if localLoopbackListenUnavailable(err) {
			t.Skipf("localhost listener is not available in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer loopback.Close()

	if got, want := loopback.CallbackURL(), "http://localhost:3000/callback"; got != want {
		t.Fatalf("CallbackURL() = %q, want %q", got, want)
	}
}

func TestOAuthLoopbackEndToEnd(t *testing.T) {
	loopback := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{State: "csrf-state"})
	defer loopback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := make(chan oauthLoopbackWaitResult, 1)
	go func() {
		result, err := loopback.Wait(ctx)
		resultCh <- oauthLoopbackWaitResult{result: result, err: err}
	}()

	resp, err := http.Get(loopback.CallbackURL() + "?code=auth-code&state=csrf-state")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Signed in with TrustedRouter") {
		t.Fatalf("response = %d %s", resp.StatusCode, body)
	}

	wait := <-resultCh
	if wait.err != nil {
		t.Fatal(wait.err)
	}
	if wait.result.Code != "auth-code" || wait.result.State != "csrf-state" {
		t.Fatalf("result = %#v", wait.result)
	}
	if err := loopback.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

func TestOAuthLoopbackDoubleCallbackPreservesFirstResult(t *testing.T) {
	loopback := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{State: "csrf-state"})
	defer loopback.Close()

	firstBody, firstStatus := getLoopbackPage(t, loopback.CallbackURL()+"?code=first-code&state=csrf-state")
	if firstStatus != http.StatusOK || !strings.Contains(firstBody, "Signed in with TrustedRouter") {
		t.Fatalf("first response = %d %s", firstStatus, firstBody)
	}
	secondBody, secondStatus := getLoopbackPage(t, loopback.CallbackURL()+"?code=second-code&state=csrf-state")
	if secondStatus != http.StatusOK || !strings.Contains(secondBody, "Signed in with TrustedRouter") {
		t.Fatalf("second response = %d %s", secondStatus, secondBody)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := loopback.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != "first-code" || result.State != "csrf-state" {
		t.Fatalf("result = %#v", result)
	}
}

func TestOAuthLoopbackRejectsStateMismatch(t *testing.T) {
	loopback := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{State: "expected"})
	defer loopback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := make(chan oauthLoopbackWaitResult, 1)
	go func() {
		result, err := loopback.Wait(ctx)
		resultCh <- oauthLoopbackWaitResult{result: result, err: err}
	}()

	resp, err := http.Get(loopback.CallbackURL() + "?code=auth-code&state=wrong")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "OAuth state mismatch") {
		t.Fatalf("response = %d %s", resp.StatusCode, body)
	}
	wait := <-resultCh
	if wait.err == nil || !strings.Contains(wait.err.Error(), "OAuth state mismatch") {
		t.Fatalf("wait err = %v", wait.err)
	}
}

func TestOAuthLoopbackRejectsOAuthErrorCallback(t *testing.T) {
	loopback := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{State: "expected"})
	defer loopback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := make(chan oauthLoopbackWaitResult, 1)
	go func() {
		result, err := loopback.Wait(ctx)
		resultCh <- oauthLoopbackWaitResult{result: result, err: err}
	}()

	body, status := getLoopbackPage(t, loopback.CallbackURL()+"?error=access_denied&error_description=Denied+by+user")
	if status != http.StatusBadRequest || !strings.Contains(body, "OAuth error: access_denied - Denied by user") {
		t.Fatalf("response = %d %s", status, body)
	}
	wait := <-resultCh
	if wait.err == nil || !strings.Contains(wait.err.Error(), "OAuth error: access_denied - Denied by user") {
		t.Fatalf("wait err = %v", wait.err)
	}
}

func TestOAuthLoopbackRejectsMissingCode(t *testing.T) {
	loopback := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{State: "expected"})
	defer loopback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := make(chan oauthLoopbackWaitResult, 1)
	go func() {
		result, err := loopback.Wait(ctx)
		resultCh <- oauthLoopbackWaitResult{result: result, err: err}
	}()

	body, status := getLoopbackPage(t, loopback.CallbackURL()+"?state=expected")
	if status != http.StatusBadRequest || !strings.Contains(body, "OAuth callback missing &#39;code&#39;") {
		t.Fatalf("response = %d %s", status, body)
	}
	wait := <-resultCh
	if wait.err == nil || !strings.Contains(wait.err.Error(), "OAuth callback missing 'code'") {
		t.Fatalf("wait err = %v", wait.err)
	}
}

func TestOAuthLoopbackCustomSuccessAndDenyHTML(t *testing.T) {
	success := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{
		State:       "expected",
		SuccessHTML: "<html><body>custom success</body></html>",
	})
	defer success.Close()
	body, status := getLoopbackPage(t, success.CallbackURL()+"?code=auth-code&state=expected")
	if status != http.StatusOK || body != "<html><body>custom success</body></html>" {
		t.Fatalf("success response = %d %s", status, body)
	}

	deny := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{
		State:    "expected",
		DenyHTML: "<html><body>custom deny: {{message}}</body></html>",
	})
	defer deny.Close()
	body, status = getLoopbackPage(t, deny.CallbackURL()+"?state=expected")
	if status != http.StatusBadRequest || body != "<html><body>custom deny: OAuth callback missing &#39;code&#39;</body></html>" {
		t.Fatalf("deny response = %d %s", status, body)
	}
}

func TestOAuthLoopbackWaitTimeoutClosesListener(t *testing.T) {
	loopback := startOAuthLoopbackForTest(t, OAuthLoopbackOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := loopback.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if err := loopback.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

type oauthLoopbackWaitResult struct {
	result OAuthLoopbackResult
	err    error
}

func startOAuthLoopbackForTest(t *testing.T, opts OAuthLoopbackOptions) *OAuthLoopback {
	t.Helper()
	if opts.Port == 0 && !opts.EphemeralPort {
		opts.EphemeralPort = true
	}
	loopback, err := StartOAuthLoopback(opts)
	if err != nil {
		if localLoopbackListenUnavailable(err) {
			t.Skipf("localhost listeners are not permitted in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	return loopback
}

func getLoopbackPage(t *testing.T, requestURL string) (string, int) {
	t.Helper()
	resp, err := http.Get(requestURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(body), resp.StatusCode
}

func localLoopbackListenUnavailable(err error) bool {
	message := err.Error()
	return strings.Contains(message, "operation not permitted") || strings.Contains(message, "address already in use")
}

package trustedrouter

import (
	"context"
	"strings"
	"testing"
)

// Property tests for the attestation policy boundary.
//
// The law is a soundness statement about VerifyGatewayAttestation:
//
//	for every claims set K and policy P,
//	    verification succeeds  =>  K's image identity was in P's accepted set
//
// Before the non-vacuity guard this was false, and falsifiably so: a trust
// release carrying no image fields (a truncated body, an error page that parsed
// as JSON, a schema change) produced a policy whose accepted sets were both
// empty, and both image checks are guarded on a non-empty accepted set:
//
//	if len(acceptedImageDigests) > 0 && !containsSafeString(...) { return err }
//
// An empty set makes the condition false and SKIPS the check. Verification then
// succeeded for any genuinely-attested Confidential Space workload while
// reporting success, so the caller believed it had pinned a build and had not.
//
// This mirrors tests/test_attestation_properties.py in trusted-router-py and
// test/attestation-properties.test.js in trusted-router-js. Go's fuzzing
// support drives the quantified cases; the seed corpus pins the shapes a
// degraded HTTP response actually takes.

// FuzzVerifiedDigestIsAlwaysInTheAcceptedSet is the law itself: accepting
// implies the workload digest was pinned. Stated as an implication rather than
// as positive/negative examples, because the defect was precisely a policy
// shape under which the implication held vacuously.
func FuzzVerifiedDigestIsAlwaysInTheAcceptedSet(f *testing.F) {
	f.Add("sha256:feedface", "sha256:feedface")
	f.Add("sha256:feedface", "sha256:other")
	f.Add("", "sha256:feedface")
	f.Add("sha256:feedface", "")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, accepted, workload string) {
		fixture := newAttestationFixture(t)
		policy := fixture.policy
		policy.ExpectedCertSHA256 = ""
		policy.ExpectedImageDigest = accepted
		policy.ExpectedImageDigests = nil
		policy.ExpectedImageReference = ""
		policy.ExpectedImageReferences = nil

		claims := fixture.claims(map[string]any{
			"submods": map[string]any{"container": map[string]any{
				"image_digest":    workload,
				"image_reference": fixture.imageReference,
			}},
		})

		result, err := VerifyGatewayAttestation(context.Background(), fixture.mint(t, claims),
			VerifyGatewayAttestationOptions{Policy: policy, JWKS: fixture.jwks})
		if err != nil {
			return // rejection is always sound
		}
		if accepted == "" {
			t.Fatalf("verification succeeded against a policy pinning no image identity")
		}
		if result.ImageDigest != accepted {
			t.Fatalf("accepted workload digest %q which is not the pinned %q", workload, accepted)
		}
	})
}

// FuzzPolicyFromReleaseIsNeverVacuous covers the input path that made the law
// reachable. Quantifies over malformed releases specifically: missing fields,
// empty strings and empty lists are all shapes a degraded HTTP response takes,
// and each one used to silently produce an unpinned policy.
func FuzzPolicyFromReleaseIsNeverVacuous(f *testing.F) {
	f.Add("", "", false, false)
	f.Add("sha256:abc", "", false, false)
	f.Add("", "registry/img:tag", false, false)
	f.Add("", "", true, true)

	f.Fuzz(func(t *testing.T, digest, reference string, listDigest, listReference bool) {
		release := &TrustRelease{ImageDigest: digest, ImageReference: reference}
		if listDigest && digest != "" {
			release.AcceptedImageDigests = []string{digest}
		}
		if listReference && reference != "" {
			release.AcceptedImageReferences = []string{reference}
		}

		policy, err := PolicyFromTrustRelease(context.Background(),
			PolicyFromTrustReleaseOptions{Release: release})
		if err != nil {
			if !strings.Contains(err.Error(), "pins no image identity") {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if !policy.PinsImageIdentity() {
			t.Fatalf("built an unpinned policy from %+v", release)
		}
	})
}

func TestPolicyFromEmptyReleaseIsRefused(t *testing.T) {
	_, err := PolicyFromTrustRelease(context.Background(),
		PolicyFromTrustReleaseOptions{Release: &TrustRelease{}})
	if err == nil {
		t.Fatal("expected an empty trust release to be refused")
	}
	if !strings.Contains(err.Error(), "pins no image identity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyWithOnlyOneIdentityKindIsAccepted(t *testing.T) {
	// Non-vacuity requires one of the two, not both.
	policy, err := PolicyFromTrustRelease(context.Background(),
		PolicyFromTrustReleaseOptions{Release: &TrustRelease{ImageDigest: "sha256:beef"}})
	if err != nil {
		t.Fatalf("PolicyFromTrustRelease returned error: %v", err)
	}
	if !policy.PinsImageIdentity() {
		t.Fatal("a digest-only policy must pin image identity")
	}
	if len(policy.ExpectedImageReferences) != 0 {
		t.Fatalf("unexpected references: %v", policy.ExpectedImageReferences)
	}
}

func TestVerificationRefusesAHandBuiltVacuousPolicy(t *testing.T) {
	// Defence in depth: the guard must not depend on going through the builder.
	fixture := newAttestationFixture(t)
	_, err := VerifyGatewayAttestation(context.Background(),
		fixture.mint(t, fixture.claims(nil)),
		VerifyGatewayAttestationOptions{
			Policy: AttestationPolicy{GCPAudience: defaultAttestationAudience},
			JWKS:   fixture.jwks,
		})
	if err == nil {
		t.Fatal("expected verification against an unpinned policy to be refused")
	}
	if !strings.Contains(err.Error(), "pins no image identity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCertOnlyPolicyIsRefused(t *testing.T) {
	// Pinning the TLS cert alone says nothing about which build answered.
	fixture := newAttestationFixture(t)
	_, err := VerifyGatewayAttestation(context.Background(),
		fixture.mint(t, fixture.claims(nil)),
		VerifyGatewayAttestationOptions{
			Policy: AttestationPolicy{
				GCPAudience:        defaultAttestationAudience,
				ExpectedCertSHA256: fixture.certSHA,
			},
			JWKS: fixture.jwks,
		})
	if err == nil {
		t.Fatal("expected a cert-only policy to be refused")
	}
	if !strings.Contains(err.Error(), "pins no image identity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPinsImageIdentityAgreesWithTheChecksItGuards keeps the guard and the two
// conditions that enable the image checks in lockstep. If they ever drift apart
// the hole reopens silently.
func TestPinsImageIdentityAgreesWithTheChecksItGuards(t *testing.T) {
	values := []string{"", "x"}
	lists := [][]string{nil, {"y"}}
	for _, digest := range values {
		for _, reference := range values {
			for _, digests := range lists {
				for _, references := range lists {
					policy := AttestationPolicy{
						ExpectedImageDigest:     digest,
						ExpectedImageDigests:    digests,
						ExpectedImageReference:  reference,
						ExpectedImageReferences: references,
					}
					digestCheckRuns := len(policy.ExpectedImageDigests) > 0 || policy.ExpectedImageDigest != ""
					referenceCheckRuns := len(policy.ExpectedImageReferences) > 0 || policy.ExpectedImageReference != ""
					if got, want := policy.PinsImageIdentity(), digestCheckRuns || referenceCheckRuns; got != want {
						t.Fatalf("PinsImageIdentity()=%v want %v for %+v", got, want, policy)
					}
				}
			}
		}
	}
}

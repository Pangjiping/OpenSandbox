// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signature

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRouteToken_RightSplit(t *testing.T) {
	id, port, sig, err := ParseRouteToken("alpha-beta-8080-abcdef12ab")
	assert.NoError(t, err)
	assert.Equal(t, "alpha-beta", id)
	assert.Equal(t, 8080, port)
	assert.Equal(t, "abcdef12ab", sig)

	id, port, sig, err = ParseRouteToken("sandbox-8080")
	assert.NoError(t, err)
	assert.Equal(t, "sandbox", id)
	assert.Equal(t, 8080, port)
	assert.Equal(t, "", sig)

	_, _, _, err = ParseRouteToken("only-two")
	assert.Error(t, err)
}

func TestParseRouteToken_LeadingZeroPort(t *testing.T) {
	_, _, _, err := ParseRouteToken("sb-08080-abcdef12ab")
	assert.Error(t, err)
}

func TestInnerAndExpectedHex8(t *testing.T) {
	secret := []byte{0x01, 0x02, 0x03}
	canonical := CanonicalBytes("sb", 42)
	inner := Inner(secret, canonical)
	assert.Len(t, inner, 4+len(secret)+4+len(canonical))
	h := ExpectedHex8(inner)
	assert.Len(t, h, 8)
	for _, c := range h {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'), "got %q", h)
	}
}

func TestVerifySignature_OKAnd401(t *testing.T) {
	secret := []byte("test-secret-bytes")
	sb := "my-sandbox"
	port := 9000
	hex8 := ExpectedHex8(Inner(secret, CanonicalBytes(sb, port)))
	sig := hex8 + "z9"

	v := &Verifier{Keys: map[string][]byte{"z9": secret}}
	assert.NoError(t, v.VerifySignature(sig, sb, port))

	badSig := "00000000z9"
	err := v.VerifySignature(badSig, sb, port)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))

	err = v.VerifySignature(hex8+"xx", sb, port)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))
}

func TestHTTPStatusForErr(t *testing.T) {
	assert.Equal(t, http.StatusUnauthorized, HTTPStatusForErr(fmt.Errorf("%w: x", ErrUnauthorized)))
	assert.Equal(t, http.StatusBadRequest, HTTPStatusForErr(fmt.Errorf("bad format")))
	assert.Equal(t, 0, HTTPStatusForErr(nil))
	assert.Equal(t, http.StatusUnauthorized, HTTPStatusForIngressErr(ErrSecureHeaderMismatch))
	assert.Equal(t, http.StatusUnauthorized, HTTPStatusForIngressErr(ErrSignatureRequired))
	assert.Equal(t, http.StatusServiceUnavailable, HTTPStatusForIngressErr(ErrVerifierNotConfigured))
}

func TestCheckIngressSecureAccess(t *testing.T) {
	secret := []byte("k")
	v := &Verifier{Keys: map[string][]byte{"z9": secret}}
	sb, port := "s", 1
	sig := ExpectedHex8(Inner(secret, CanonicalBytes(sb, port))) + "z9"

	assert.NoError(t, CheckIngressSecureAccess(IngressAccessInput{
		Secure:    false,
		Signature: sig,
		SandboxID: sb,
		Port:      port,
		Verifier:  v,
	}))

	assert.NoError(t, CheckIngressSecureAccess(IngressAccessInput{
		Secure:               true,
		ExpectedAccessToken:  "tok",
		RequestedAccessToken: "tok",
		Signature:            "bad",
		SandboxID:            sb,
		Port:                 port,
	}))

	assert.ErrorIs(t, CheckIngressSecureAccess(IngressAccessInput{
		Secure:               true,
		ExpectedAccessToken:  "tok",
		RequestedAccessToken: "nope",
		Signature:            sig,
		SandboxID:            sb,
		Port:                 port,
		Verifier:             v,
	}), ErrSecureHeaderMismatch)

	assert.ErrorIs(t, CheckIngressSecureAccess(IngressAccessInput{
		Secure:               true,
		ExpectedAccessToken:  "tok",
		RequestedAccessToken: "",
		Signature:            sig,
		SandboxID:            sb,
		Port:                 port,
		Verifier:             nil,
	}), ErrVerifierNotConfigured)

	assert.NoError(t, CheckIngressSecureAccess(IngressAccessInput{
		Secure:               true,
		ExpectedAccessToken:  "tok",
		RequestedAccessToken: "",
		Signature:            sig,
		SandboxID:            sb,
		Port:                 port,
		Verifier:             v,
	}))

	assert.ErrorIs(t, CheckIngressSecureAccess(IngressAccessInput{
		Secure:               true,
		ExpectedAccessToken:  "tok",
		RequestedAccessToken: "",
		Signature:            "",
		SandboxID:            sb,
		Port:                 port,
	}), ErrSignatureRequired)
}

func TestParseKeys(t *testing.T) {
	raw := []byte{0xab, 0xcd}
	keys, err := ParseKeys("k1=" + base64.StdEncoding.EncodeToString(raw))
	assert.NoError(t, err)
	assert.Equal(t, raw, keys["k1"])

	_, err = ParseKeys("")
	assert.Error(t, err)

	_, err = ParseKeys("K1=" + base64.StdEncoding.EncodeToString(raw))
	assert.Error(t, err)
}

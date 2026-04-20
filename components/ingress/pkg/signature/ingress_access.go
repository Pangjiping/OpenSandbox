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
	"errors"
	"net/http"
	"strings"
)

const (
	OpenSandboxSecureAccessHeader = "OpenSandbox-Secure-Access"
)

var (
	OpenSandboxSecureAccessCanonical = http.CanonicalHeaderKey(OpenSandboxSecureAccessHeader)

	ErrSecureHeaderMismatch  = errors.New("signature: secure access header mismatch")
	ErrSignatureRequired     = errors.New("signature: signature required for this sandbox")
	ErrVerifierNotConfigured = errors.New("signature: ingress verifier not configured")
)

func SecureAccessHeaderFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(OpenSandboxSecureAccessCanonical))
}

func secureAccessHeaderMatches(headerValue, requireToken string) bool {
	if requireToken == "" || headerValue == "" {
		return false
	}

	return headerValue == requireToken
}

type IngressAccessInput struct {
	Secure               bool
	ExpectedAccessToken  string
	RequestedAccessToken string
	Signature            string
	SandboxID            string
	Port                 int
	Verifier             *Verifier
}

func CheckIngressSecureAccess(in IngressAccessInput) error {
	if !in.Secure {
		return nil
	}

	at := strings.TrimSpace(in.ExpectedAccessToken)
	hv := strings.TrimSpace(in.RequestedAccessToken)
	if hv != "" {
		if secureAccessHeaderMatches(hv, at) {
			return nil
		}
		return ErrSecureHeaderMismatch
	}
	if in.Signature != "" {
		if in.Verifier == nil || !in.Verifier.Enabled() {
			return ErrVerifierNotConfigured
		}
		return in.Verifier.VerifySignature(in.Signature, in.SandboxID, in.Port)
	}
	return ErrSignatureRequired
}

func HTTPStatusForIngressErr(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrUnauthorized) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, ErrSecureHeaderMismatch) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, ErrSignatureRequired) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, ErrVerifierNotConfigured) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

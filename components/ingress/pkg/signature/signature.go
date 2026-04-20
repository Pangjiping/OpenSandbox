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

// Package signature implements OSEP-0011 route signature construction and verification (GetEndpoint secure access).
package signature

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrUnauthorized = errors.New("signature: unauthorized")

type Verifier struct {
	Keys map[string][]byte
}

func (v *Verifier) Enabled() bool {
	return v != nil && len(v.Keys) > 0
}

// ParseKeys parses ingress --secure-access-keys: "k1=BASE64,k2=BASE64" (comma-separated, key_id exactly 2 chars [0-9a-z]).
func ParseKeys(s string) (map[string][]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("empty keys string")
	}
	out := make(map[string][]byte)
	for _, seg := range strings.Split(s, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		key, val, ok := strings.Cut(seg, "=")
		if !ok || key == "" || val == "" {
			return nil, fmt.Errorf("invalid keys segment %q (want key_id=base64)", seg)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(key) != 2 {
			return nil, fmt.Errorf("key_id must be exactly 2 characters, got %q", key)
		}
		for _, r := range key {
			if r >= 'A' && r <= 'Z' {
				return nil, fmt.Errorf("key_id must be lowercase [0-9a-z], got %q", key)
			}
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
				return nil, fmt.Errorf("key_id must be [0-9a-z], got %q", key)
			}
		}
		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, fmt.Errorf("decode secret for key %q: %w", key, err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("empty secret for key %q", key)
		}
		out[key] = raw
	}
	if len(out) == 0 {
		return nil, errors.New("no keys parsed")
	}
	return out, nil
}

func ValidateSignatureFormat(signature string) error {
	if len(signature) != 10 {
		return fmt.Errorf("signature must be 10 characters, got %d", len(signature))
	}
	for i := 0; i < 8; i++ {
		c := signature[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("signature hex8 must be lowercase hex")
		}
	}
	for i := 8; i < 10; i++ {
		c := signature[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return fmt.Errorf("signed_key_id must be [0-9a-z]")
		}
	}
	return nil
}

func ParsePortSegment(portStr string) (int, error) {
	if len(portStr) > 1 && portStr[0] == '0' {
		return 0, fmt.Errorf("port must not have leading zeros")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", portStr)
	}
	return p, nil
}

func ParseRouteToken(s string) (sandboxID string, port int, signature string, err error) {
	parts := strings.Split(s, "-")
	switch len(parts) {
	case 0, 1:
		return "", 0, "", fmt.Errorf("expected <sandbox-id>-<port> or <sandbox-id>-<port>-<signature>, got %d segments", len(parts))
	case 2:
		sandboxID = parts[0]
		if sandboxID == "" {
			return "", 0, "", fmt.Errorf("empty sandbox_id")
		}
		p, perr := ParsePortSegment(parts[1])
		if perr != nil {
			return "", 0, "", perr
		}
		return sandboxID, p, "", nil
	default:
		signature = parts[len(parts)-1]
		if err := ValidateSignatureFormat(signature); err != nil {
			return "", 0, "", err
		}
		portStr := parts[len(parts)-2]
		p, err := ParsePortSegment(portStr)
		if err != nil {
			return "", 0, "", err
		}
		sandboxID = strings.Join(parts[:len(parts)-2], "-")
		if sandboxID == "" {
			return "", 0, "", fmt.Errorf("empty sandbox_id")
		}
		return sandboxID, p, signature, nil
	}
}

func CanonicalBytes(sandboxID string, port int) []byte {
	return []byte(fmt.Sprintf("v1\nshort\n%s\n%d\n", sandboxID, port))
}

func Inner(secret, canonical []byte) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(secret)))
	buf = append(buf, secret...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(canonical)))
	buf = append(buf, canonical...)
	return buf
}

func ExpectedHex8(inner []byte) string {
	sum := sha256.Sum256(inner)
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 4; i++ {
		b := sum[i]
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

func (v *Verifier) VerifySignature(signature, sandboxID string, port int) error {
	if !v.Enabled() {
		return nil
	}

	if err := ValidateSignatureFormat(signature); err != nil {
		return err
	}
	hex8 := signature[:8]
	signedKeyID := signature[8:10]
	secret, ok := v.Keys[signedKeyID]
	if !ok {
		return fmt.Errorf("%w: unknown signed_key_id", ErrUnauthorized)
	}

	canonical := CanonicalBytes(sandboxID, port)
	inner := Inner(secret, canonical)
	want := ExpectedHex8(inner)
	if hex8 != want {
		return fmt.Errorf("%w: signature mismatch", ErrUnauthorized)
	}

	return nil
}

func HTTPStatusForErr(err error) int {
	return HTTPStatusForIngressErr(err)
}

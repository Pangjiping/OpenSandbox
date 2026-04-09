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

package dnsproxy

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
)

func TestUpstreamProbeIntervalFromEnv(t *testing.T) {
	t.Setenv(constants.EnvDNSUpstreamProbeIntervalSec, "")
	require.Equal(t, defaultUpstreamProbeInterval, upstreamProbeIntervalFromEnv())

	t.Setenv(constants.EnvDNSUpstreamProbeIntervalSec, "5")
	require.Equal(t, 5*time.Second, upstreamProbeIntervalFromEnv())

	t.Setenv(constants.EnvDNSUpstreamProbeIntervalSec, "not-a-number")
	require.Equal(t, defaultUpstreamProbeInterval, upstreamProbeIntervalFromEnv())
}

func TestUpstreamProbeFromEnv(t *testing.T) {
	t.Setenv(constants.EnvDNSUpstreamProbe, "")
	n, qt := upstreamProbeFromEnv()
	require.Equal(t, ".", n)
	require.Equal(t, uint16(dns.TypeNS), qt)

	t.Setenv(constants.EnvDNSUpstreamProbe, ".")
	n, qt = upstreamProbeFromEnv()
	require.Equal(t, ".", n)
	require.Equal(t, uint16(dns.TypeNS), qt)

	t.Setenv(constants.EnvDNSUpstreamProbe, "intranet.corp")
	n, qt = upstreamProbeFromEnv()
	require.Equal(t, "intranet.corp.", n)
	require.Equal(t, uint16(dns.TypeA), qt)
}

func TestNormalizeEnvUpstreamAddr(t *testing.T) {
	got, err := normalizeEnvUpstreamAddr("8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8:53", got)

	got, err = normalizeEnvUpstreamAddr("1.1.1.1:5353")
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1:5353", got)

	got, err = normalizeEnvUpstreamAddr("2001:db8::1")
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::1]:53", got)

	got, err = normalizeEnvUpstreamAddr("[2001:db8::2]:853")
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::2]:853", got)

	got, err = normalizeEnvUpstreamAddr("[2001:db8::3]")
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::3]:53", got)

	_, err = normalizeEnvUpstreamAddr("")
	require.Error(t, err)

	_, err = normalizeEnvUpstreamAddr("dns.google")
	require.Error(t, err)

	_, err = normalizeEnvUpstreamAddr("dns.google:53")
	require.Error(t, err)
}

func TestParseEnvDNSUpstreams(t *testing.T) {
	got, err := parseEnvDNSUpstreams("8.8.8.8,1.1.1.1")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.8:53", "1.1.1.1:53"}, got)

	got, err = parseEnvDNSUpstreams("8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.8:53"}, got)

	got, err = parseEnvDNSUpstreams("8.8.8.8, 8.8.8.8, 1.1.1.1")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.8:53", "1.1.1.1:53"}, got)

	_, err = parseEnvDNSUpstreams("dns.google,8.8.8.8")
	require.Error(t, err)
}

func TestAllowIPsFromUpstreamAddrs(t *testing.T) {
	ips := AllowIPsFromUpstreamAddrs([]string{"8.8.8.8:53", "1.1.1.1:53", "resolver.example.com:53"})
	require.Len(t, ips, 2)
	require.Equal(t, "8.8.8.8", ips[0].String())
	require.Equal(t, "1.1.1.1", ips[1].String())
}

func TestShouldFailoverAfterResponse(t *testing.T) {
	p2 := &Proxy{upstreams: []string{"198.51.100.254:53", "8.8.8.8:53"}}
	const n = 2

	emptyOK := new(dns.Msg)
	emptyOK.Rcode = dns.RcodeSuccess
	try, _ := p2.shouldFailoverAfterResponse(emptyOK, 0, n)
	require.True(t, try, "empty NOERROR on first upstream should failover")

	try, _ = p2.shouldFailoverAfterResponse(emptyOK, 1, n)
	require.False(t, try, "empty NOERROR on last upstream should not failover")

	withA := new(dns.Msg)
	withA.Rcode = dns.RcodeSuccess
	withA.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "x."}, A: net.ParseIP("1.1.1.1")}}
	try, _ = p2.shouldFailoverAfterResponse(withA, 0, n)
	require.False(t, try)

	nx := new(dns.Msg)
	nx.Rcode = dns.RcodeNameError
	try, _ = p2.shouldFailoverAfterResponse(nx, 0, n)
	require.False(t, try)

	sf := new(dns.Msg)
	sf.Rcode = dns.RcodeServerFailure
	try, _ = p2.shouldFailoverAfterResponse(sf, 0, n)
	require.True(t, try)
}

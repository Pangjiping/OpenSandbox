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

//go:build linux

package httpproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux nf netfilter: IPv6 original destination uses the same option number as IPv4 SO_ORIGINAL_DST.
const ip6OriginalDst = unix.SO_ORIGINAL_DST

func getOriginalDst(conn net.Conn) (netip.AddrPort, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("connection is not TCP")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ap netip.AddrPort
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		ap, opErr = originalDstFromFD(fd)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return ap, opErr
}

func originalDstFromFD(fd uintptr) (netip.AddrPort, error) {
	var sa4 unix.RawSockaddrInet4
	l4 := uint32(unsafe.Sizeof(sa4))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IP, unix.SO_ORIGINAL_DST,
		uintptr(unsafe.Pointer(&sa4)), uintptr(unsafe.Pointer(&l4)), 0)
	if errno == 0 {
		return sockaddrInet4ToAddrPort(&sa4)
	}
	var sa6 unix.RawSockaddrInet6
	l6 := uint32(unsafe.Sizeof(sa6))
	_, _, errno6 := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IPV6, ip6OriginalDst,
		uintptr(unsafe.Pointer(&sa6)), uintptr(unsafe.Pointer(&l6)), 0)
	if errno6 == 0 {
		return sockaddrInet6ToAddrPort(&sa6)
	}
	return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %v %v", errno, errno6)
}

func sockaddrInet4ToAddrPort(sa *unix.RawSockaddrInet4) (netip.AddrPort, error) {
	port := binary.BigEndian.Uint16(unsafe.Slice((*byte)(unsafe.Pointer(&sa.Port)), 2))
	ip := netip.AddrFrom4([4]byte(sa.Addr))
	return netip.AddrPortFrom(ip, port), nil
}

func sockaddrInet6ToAddrPort(sa *unix.RawSockaddrInet6) (netip.AddrPort, error) {
	port := binary.BigEndian.Uint16(unsafe.Slice((*byte)(unsafe.Pointer(&sa.Port)), 2))
	ip := netip.AddrFrom16(sa.Addr)
	return netip.AddrPortFrom(ip, port), nil
}

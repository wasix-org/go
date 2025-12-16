// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

package net

import (
	"internal/poll"
)

func newPollFD(net string, pfd poll.FD) *netFD {
	var laddr Addr
	var raddr Addr
	// WASI preview 1 does not have functions like getsockname/getpeername,
	// so we cannot get access to the underlying IP address used by connections.
	//
	// However, listeners created by FileListener are of type *TCPListener,
	// which can be asserted by a Go program. The (*TCPListener).Addr method
	// documents that the returned value will be of type *TCPAddr, we satisfy
	// the documented behavior by creating addresses of the expected type here.
	switch net {
	case "tcp":
		laddr = new(TCPAddr)
		raddr = new(TCPAddr)
	case "udp":
		laddr = new(UDPAddr)
		raddr = new(UDPAddr)
	default:
		laddr = unknownAddr{}
		raddr = unknownAddr{}
	}
	return &netFD{
		pfd:   pfd,
		net:   net,
		laddr: laddr,
		raddr: raddr,
	}
}

type unknownAddr struct{}

func (unknownAddr) Network() string { return "unknown" }
func (unknownAddr) String() string  { return "unknown" }

// func (fd *netFD) closeRead() error {
// 	if fd.fakeNetFD != nil {
// 		return fd.fakeNetFD.closeRead()
// 	}
// 	return fd.shutdown(syscall.SHUT_RD)
// }

// func (fd *netFD) closeWrite() error {
// 	if fd.fakeNetFD != nil {
// 		return fd.fakeNetFD.closeWrite()
// 	}
// 	return fd.shutdown(syscall.SHUT_WR)
// }

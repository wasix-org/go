// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

package syscall

import "unsafe"

const (
	SHUT_RD   = 0x1
	SHUT_WR   = 0x2
	SHUT_RDWR = SHUT_RD | SHUT_WR
)

type sdflags = uint32

//go:wasmimport wasix_32v1 sock_recv
//go:noescape
func sock_recv(fd int32,
	ri_data unsafe.Pointer,
	ri_data_len int32,
	ri_flags int32,
	ro_data_len unsafe.Pointer,
	ro_flags unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_send
//go:noescape
func sock_send(fd int32,
	si_data unsafe.Pointer,
	si_data_len int32,
	si_flags int32,
	ret_data_len unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_status
//go:noescape
func sock_status(fd int32, status unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_addr_local
//go:noescape
func sock_addr_local(fd int32,
	ret_addr unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_addr_peer
//go:noescape
func sock_addr_peer(fd int32,
	ro_addr unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_open
//go:noescape
func sock_open(family int32,
	sotype int32,
	proto int32,
	ret_fd unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_pair
//go:noescape
func sock_pair(fd1 int32,
	sotype int32,
	proto int32,
	ret_fd1 unsafe.Pointer,
	ret_fd2 unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_set_opt_flag
//go:noescape
func sock_set_opt_flag(fd int32,
	opt int32,
	flag int32) Errno

//go:wasmimport wasix_32v1 sock_get_opt_flag
//go:noescape
func sock_get_opt_flag(fd int32,
	opt int32,
	flag unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_set_opt_time
//go:noescape
func sock_set_opt_time(fd int32,
	opt int32,
	time unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_get_opt_time
//go:noescape
func sock_get_opt_time(fd int32,
	opt int32,
	ret_time unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_set_opt_size
//go:noescape
func sock_set_opt_size(fd int32,
	opt int32,
	size int64) Errno

//go:wasmimport wasix_32v1 sock_get_opt_size
//go:noescape
func sock_get_opt_size(fd int32,
	opt int32,
	ret_size unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_join_multicast_v4
//go:noescape
func sock_join_multicast_v4(fd int32,
	multiaddr unsafe.Pointer,
	interface_ unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_leave_multicast_v4
//go:noescape
func sock_leave_multicast_v4(fd int32,
	group unsafe.Pointer,
	interface_ unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_join_multicast_v6
//go:noescape
func sock_join_multicast_v6(fd int32,
	multiaddr unsafe.Pointer,
	interface_ unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_leave_multicast_v6
//go:noescape
func sock_leave_multicast_v6(fd int32,
	multiaddr unsafe.Pointer,
	interface_ unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_bind
//go:noescape
func sock_bind(fd int32,
	addr unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_listen
//go:noescape
func sock_listen(fd int32,
	backlog int32) Errno

//go:wasmimport wasix_32v1 sock_accept_v2
//go:noescape
func sock_accept_v2(fd int32, flags fdflags, newfd unsafe.Pointer, ret_addr unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_connect
//go:noescape
func sock_connect(fd int32,
	addr unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_recv_from
//go:noescape
func sock_recv_from(fd int32,
	ri_data unsafe.Pointer,
	ri_data_len int32,
	ri_flags int32,
	ro_data_len unsafe.Pointer,
	ro_flags unsafe.Pointer,
	ro_addr unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_send_to
//go:noescape
func sock_send_to(fd int32,
	si_data unsafe.Pointer,
	si_data_len int32,
	si_flags int32,
	ret_data_len unsafe.Pointer,
	to unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_send_file
//go:noescape
func sock_send_file(fd int32,
	in_fd int32,
	offset int64,
	count int64,
	ret_sent unsafe.Pointer) Errno

//go:wasmimport wasix_32v1 sock_shutdown
//go:noescape
func sock_shutdown(fd int32, flags sdflags) Errno

func Socket(proto, sotype, unused int) (fd int, err error) {
	return 0, ENOSYS
}

func setDefaultSockopts(s, family, sotype int, ipv6only bool) error {
	return ENOSYS
}

func Getsockname(fd int) (Sockaddr, error) {
	return nil, ENOSYS
}

func setDefaultMulticastSockopts(s int) error {
	return ENOSYS
}

func setDefaultListenerSockopts(s int) error {
	return ENOSYS
}

const SO_RCVBUF = 15   // Check
const SO_SNDBUF = 16   // Check
const SO_KEEPALIVE = 9 // Check
const SO_LINGER = 128  // Check

const TCP_KEEPINTVL = 0x101 // Check
const TCP_KEEPCNT = 0x102   // Check
const TCP_KEEPALIVE = 0x103 // Check
const TCP_KEEPIDLE = 0x104  // Check

const TCP_NODELAY = 1 // Check

const SOCK_NONBLOCK = 0x00004000
const SOCK_CLOEXEC = 0x00002000

const SOL_SOCKET = 0x7fffffff

func Getpeername(fd int) (Sockaddr, error) {
	return nil, ENOSYS
}

func Bind(fd int, sa Sockaddr) error {
	return ENOSYS
}

func StopIO(fd int) error {
	return ENOSYS
}

func Listen(fd int, backlog int) error {
	return ENOSYS
}

func Accept(fd int) (int, Sockaddr, error) {
	var newfd int32
	random_addr := SockaddrInet4{
		Port: 0,
		Addr: [4]byte{0, 0, 0, 0},
	}
	addr_ptr := unsafe.Pointer(&random_addr)
	errno := sock_accept_v2(int32(fd), 0, unsafe.Pointer(&newfd), addr_ptr)
	return int(newfd), nil, errnoErr(errno)
}

func Connect(fd int, sa Sockaddr) error {
	return ENOSYS
}

func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error) {
	return 0, nil, ENOSYS
}

func Sendto(fd int, p []byte, flags int, to Sockaddr) error {
	return ENOSYS
}

func Recvmsg(fd int, p, oob []byte, flags int) (n, oobn, recvflags int, from Sockaddr, err error) {
	return 0, 0, 0, nil, ENOSYS
}

func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (n int, err error) {
	return 0, ENOSYS
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	return 0, ENOSYS
}

func SetsockoptInt(fd, level, opt int, value int) error {
	return ENOSYS
}

func SetReadDeadline(fd int, t int64) error {
	return ENOSYS
}

func SetWriteDeadline(fd int, t int64) error {
	return ENOSYS
}

func Shutdown(fd int, how int) error {
	errno := sock_shutdown(int32(fd), sdflags(how))
	return errnoErr(errno)
}

type Linger struct {
	Onoff  int32
	Linger int32
}

func SetsockoptLinger(fd, level, opt int, l *Linger) (err error) {
	return ENOSYS
}

func SetsockoptInet4Addr(fd, level, opt int, value [4]byte) (err error) {
	return ENOSYS
}

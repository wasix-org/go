// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

package syscall

import (
	"internal/itoa"
	"unsafe"
)

// Constants retrieved from `api_wasix.h`
// https://github.com/wasix-org/wasix-libc/blob/3d89efe7529311a58ccd21a170d8667f3d182896/libc-bottom-half/headers/public/wasi/api_wasix.h#L1831
const (
	SHUT_RD   = 0x1
	SHUT_WR   = 0x2
	SHUT_RDWR = SHUT_RD | SHUT_WR
)

const (
	AF_UNSPEC = 0
	AF_INET   = 1
	AF_INET6  = 2
	AF_UNIX   = 3
)

const (
	// Socket types / flags (note: octal literals preserved)
	SOCK_NONBLOCK = 0o200
	SOCK_CLOEXEC  = 0o20000000
)

const (
	IPPROTO_IP   = 0
	IPPROTO_TCP  = 6
	IPPROTO_IPV4 = 4
	IPPROTO_IPV6 = 41
	IPPROTO_UDP  = 0x11
)
const (
	SOMAXCONN = 0x80
)

const (
	// TCP socket options
	TCP_NODELAY              = 1
	TCP_MAXSEG               = 2
	TCP_CORK                 = 3
	TCP_KEEPIDLE             = 4
	TCP_KEEPINTVL            = 5
	TCP_KEEPCNT              = 6
	TCP_SYNCNT               = 7
	TCP_LINGER2              = 8
	TCP_DEFER_ACCEPT         = 9
	TCP_WINDOW_CLAMP         = 10
	TCP_INFO                 = 11
	TCP_QUICKACK             = 12
	TCP_CONGESTION           = 13
	TCP_MD5SIG               = 14
	TCP_THIN_LINEAR_TIMEOUTS = 16
	TCP_THIN_DUPACK          = 17
	TCP_USER_TIMEOUT         = 18
	TCP_REPAIR               = 19
	TCP_REPAIR_QUEUE         = 20
	TCP_QUEUE_SEQ            = 21
	TCP_REPAIR_OPTIONS       = 22
	TCP_FASTOPEN             = 23
	TCP_TIMESTAMP            = 24
	TCP_NOTSENT_LOWAT        = 25
	TCP_CC_INFO              = 26
	TCP_SAVE_SYN             = 27
	TCP_SAVED_SYN            = 28
	TCP_REPAIR_WINDOW        = 29
	TCP_FASTOPEN_CONNECT     = 30
	TCP_ULP                  = 31
	TCP_MD5SIG_EXT           = 32
	TCP_FASTOPEN_KEY         = 33
	TCP_FASTOPEN_NO_COOKIE   = 34
	TCP_ZEROCOPY_RECEIVE     = 35
	TCP_INQ                  = 36
	TCP_TX_DELAY             = 37

	// Aliases
	TCP_CM_INQ = TCP_INQ
)

const (
	// TCP connection states
	TCP_ESTABLISHED = 1
	TCP_SYN_SENT    = 2
	TCP_SYN_RECV    = 3
	TCP_FIN_WAIT1   = 4
	TCP_FIN_WAIT2   = 5
	TCP_TIME_WAIT   = 6
	TCP_CLOSE       = 7
	TCP_CLOSE_WAIT  = 8
	TCP_LAST_ACK    = 9
	TCP_LISTEN      = 10
	TCP_CLOSING     = 11
)

const TCP_KEEPALIVE = 0x103 // Check

const (
	SOCK_UNUSED    = 0
	SOCK_STREAM    = 1
	SOCK_DGRAM     = 2
	SOCK_RAW       = 3
	SOCK_SEQPACKET = 4

	// Socket level
	SOL_SOCKET = 65535

	// Socket options
	SO_DEBUG      = 1
	SO_REUSEADDR  = 0x0004
	SO_KEEPALIVE  = 0x0008
	SO_DONTROUTE  = 0x0010
	SO_BROADCAST  = 0x0020
	SO_LINGER     = 0x0080
	SO_OOBINLINE  = 0x0100
	SO_REUSEPORT  = 0x0200
	SO_SNDBUF     = 0x1001
	SO_RCVBUF     = 0x1002
	SO_SNDLOWAT   = 0x1003
	SO_RCVLOWAT   = 0x1004
	SO_ERROR      = 0x1007
	SO_TYPE       = 0x1008
	SO_ACCEPTCONN = 0x1009
	SO_PROTOCOL   = 0x1028
	SO_DOMAIN     = 0x1029

	SO_NO_CHECK    = 11
	SO_PRIORITY    = 12
	SO_BSDCOMPAT   = 14
	SO_PASSCRED    = 17
	SO_PEERCRED    = 18
	SO_PEERSEC     = 30
	SO_SNDBUFFORCE = 31
	SO_RCVBUFFORCE = 33
)

const (
	_           = iota
	IPV6_V6ONLY = 26
)

// Misc constants expected by package net but not supported.
const (
	F_DUPFD_CLOEXEC = 6
	SYS_FCNTL       = 500 // unsupported
)

type Sockaddr any

type SockaddrInet4 struct {
	Port int
	Addr [4]byte
}

type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
}

type SockaddrUnix struct {
	Name string
}

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

func Socket(domain, typ, proto int) (ret_fd int, err error) {
	// Write(1, []byte("Socket.Socket\n"))
	type_ := typ & 0xF // WASIX only supports 8-bit socket types (so we remove everything else)
	if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
		if type_ == SOCK_STREAM {
			proto = IPPROTO_TCP
		} else if type_ == SOCK_DGRAM {
			proto = IPPROTO_UDP
		}
	}
	// Get the 8-bit representation of the socket type
	Write(1, []byte("Socket.Socket: domain="+itoa.Itoa(domain)+", typ="+itoa.Itoa(typ)+", typ8bits="+itoa.Itoa(int(type_))+", proto="+itoa.Itoa(proto)+"\n"))
	// fmt.Sprintf("Socket.Socket: domain=%d, typ=%d, proto=%d\n", domain, typ, proto)

	var fd int32
	errno := sock_open(int32(domain), int32(type_), int32(proto), unsafe.Pointer(&fd))
	if errno != Errno(0) {
		return 0, errnoErr(errno)
	}
	return int(fd), nil
}

func setDefaultSockopts(s, family, sotype int, ipv6only bool) error {
	Write(1, []byte("Socket.setDefaultSockopts\n"))
	return ENOSYS
}

func Getsockname(fd int) (Sockaddr, error) {
	Write(1, []byte("Socket.Getsockname\n"))
	return nil, ENOSYS
}

func setDefaultMulticastSockopts(s int) error {
	Write(1, []byte("Socket.setDefaultMulticastSockopts\n"))
	return ENOSYS
}

func setDefaultListenerSockopts(s int) error {
	Write(1, []byte("Socket.setDefaultListenerSockopts\n"))
	return ENOSYS
}

func Getpeername(fd int) (Sockaddr, error) {
	Write(1, []byte("Socket.Getpeername\n"))
	return nil, ENOSYS
}

func Bind(fd int, sa Sockaddr) error {
	Write(1, []byte("Socket.Bind\n"))
	sock_bind(int32(fd), unsafe.Pointer(&sa))
	return ENOSYS
}

func StopIO(fd int) error {
	Write(1, []byte("Socket.StopIO\n"))
	return ENOSYS
}

func Listen(fd int, backlog int) error {
	Write(1, []byte("Socket.Listen\n"))
	return ENOSYS
}

func Accept(fd int) (int, Sockaddr, error) {
	Write(1, []byte("Socket.Accept\n"))
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
	Write(1, []byte("Socket.Connect\n"))
	return ENOSYS
}

func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error) {
	Write(1, []byte("Socket.Recvfrom\n"))
	return 0, nil, ENOSYS
}

func Sendto(fd int, p []byte, flags int, to Sockaddr) error {
	Write(1, []byte("Socket.Sendto\n"))
	return ENOSYS
}

func Recvmsg(fd int, p, oob []byte, flags int) (n, oobn, recvflags int, from Sockaddr, err error) {
	Write(1, []byte("Socket.Recvmsg\n"))
	return 0, 0, 0, nil, ENOSYS
}

func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (n int, err error) {
	Write(1, []byte("Socket.SendmsgN\n"))
	return 0, ENOSYS
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	Write(1, []byte("Socket.GetsockoptInt\n"))
	return 0, ENOSYS
}

func SetsockoptInt(fd, level, opt int, value int) error {
	Write(1, []byte("Socket.SetsockoptInt\n"))
	return ENOSYS
}

func SetReadDeadline(fd int, t int64) error {
	Write(1, []byte("Socket.SetReadDeadline\n"))
	return ENOSYS
}

func SetWriteDeadline(fd int, t int64) error {
	Write(1, []byte("Socket.SetWriteDeadline\n"))
	return ENOSYS
}

func Shutdown(fd int, how int) error {
	errno := sock_shutdown(int32(fd), sdflags(how))
	Write(1, []byte("Socket.Shutdown\n"))
	return errnoErr(errno)
}

type Linger struct {
	Onoff  int32
	Linger int32
}

func SetsockoptLinger(fd, level, opt int, l *Linger) (err error) {
	Write(1, []byte("Socket.SetsockoptLinger\n"))
	return ENOSYS
}

func SetsockoptInet4Addr(fd, level, opt int, value [4]byte) (err error) {
	Write(1, []byte("Socket.SetsockoptInet4Addr\n"))
	return ENOSYS
}

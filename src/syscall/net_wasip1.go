// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

package syscall

import (
	"unsafe"
)

// Constants retrieved from `api_wasix.h`
// https://github.com/wasix-org/wasix-libc/blob/3d89efe7529311a58ccd21a170d8667f3d182896/libc-bottom-half/headers/public/wasi/api_wasix.h#L1831
const (
	SHUT_RD   = 0x1
	SHUT_WR   = 0x2
	SHUT_RDWR = SHUT_RD | SHUT_WR
)

// Address families
const (
	AF_UNSPEC = 0
	AF_INET   = 1
	AF_INET6  = 2
	AF_UNIX   = 3
)

// Socket types / flags (note: octal literals preserved)
const (
	SOCK_NONBLOCK = 0o200
	SOCK_CLOEXEC  = 0o20000000
)

const (
	MSG_DONTWAIT = 0x0040
)

// Protocol families
const (
	IPPROTO_IP   = 0
	IPPROTO_TCP  = 6
	IPPROTO_IPV4 = 4
	IPPROTO_IPV6 = 41
	IPPROTO_UDP  = 0x11
)

// Miscellaneous constants
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
	SO_KEEPALIVE  = 12
	SO_BROADCAST  = 6
	SO_LINGER     = 13
	SO_OOBINLINE  = 14
	SO_REUSEPORT  = 1
	SO_SNDBUF     = 16
	SO_RCVBUF     = 15
	SO_SNDLOWAT   = 18
	SO_RCVLOWAT   = 17
	SO_ERROR      = 0x1007
	SO_TYPE       = 0x1008
	SO_ACCEPTCONN = 0x1009
	SO_PROTOCOL   = 26
	SO_DOMAIN     = 0x1029

	SO_RCVTIMEO  = 19
	SO_SNDTIMEO  = 20
	SO_CONNTIMEO = 21
	SO_ACCPTIMEO = 22

	SO_REUSE_PORT        = 1
	SO_REUSE_ADDR        = 2
	SO_TTL               = 23
	SO_MULTICAST_TTL_V4  = 24
	SO_NODELAY           = 3
	SO_DONTROUTE         = 4
	SO_V6ONLY            = 5
	SO_MULTICAST_LOOP_V4 = 7
	SO_MULTICAST_LOOP_V6 = 8
	SO_NO_CHECK          = 11
	SO_PRIORITY          = 12
	SO_BSDCOMPAT         = 14
	SO_PASSCRED          = 17
	SO_PEERCRED          = 18
	SO_PEERSEC           = 30
	SO_SNDBUFFORCE       = 31
	SO_RCVBUFFORCE       = 33
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

type AddressFamily uint8

type RawSockaddrWithPortAny struct {
	Tag    AddressFamily
	_      byte // padding
	Octets [18]byte
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

func sockaddrInet4ToRawWithPort(rsa *RawSockaddrWithPortAny, sa *SockaddrInet4) int32 {
	rsa.Tag = AF_INET

	// Port (native endian, matches Rust from_ne_bytes)
	rsa.Octets[0] = byte(sa.Port)
	rsa.Octets[1] = byte(sa.Port >> 8)

	// IPv4 address
	copy(rsa.Octets[2:6], sa.Addr[:])

	return int32(unsafe.Sizeof(*rsa))
}

func sockaddrInet6ToRawWithPort(rsa *RawSockaddrWithPortAny, sa *SockaddrInet6) int32 {
	*rsa = RawSockaddrWithPortAny{} // zero everything

	rsa.Tag = AF_INET6

	// Port (native endian)
	rsa.Octets[0] = byte(sa.Port)
	rsa.Octets[1] = byte(sa.Port >> 8)

	// IPv6 address
	copy(rsa.Octets[2:18], sa.Addr[:])

	return int32(unsafe.Sizeof(*rsa))
}

func rawWithPortToSockaddrInet4(rsa *RawSockaddrWithPortAny, sa *SockaddrInet4) error {
	if rsa.Tag != AF_INET {
		return EAFNOSUPPORT
	}

	sa.Port = int(uint16(rsa.Octets[0]) | uint16(rsa.Octets[1])<<8)
	copy(sa.Addr[:], rsa.Octets[2:6])
	return nil
}

func rawWithPortToSockaddrInet6(rsa *RawSockaddrWithPortAny, sa *SockaddrInet6) error {
	if rsa.Tag != AF_INET6 {
		return EAFNOSUPPORT
	}

	sa.Port = int(uint16(rsa.Octets[0]) | uint16(rsa.Octets[1])<<8)
	copy(sa.Addr[:], rsa.Octets[2:18])
	return nil
}

func sockaddrToRawWithPort(sa Sockaddr) (*RawSockaddrWithPortAny, error) {

	switch sa := sa.(type) {
	case *SockaddrInet4:
		raw_sa := new(RawSockaddrWithPortAny) // zero everything
		sockaddrInet4ToRawWithPort(raw_sa, sa)
		return raw_sa, nil
	case *SockaddrInet6:
		raw_sa := new(RawSockaddrWithPortAny) // zero everything
		sockaddrInet6ToRawWithPort(raw_sa, sa)
		return raw_sa, nil
	default:
		return nil, EAFNOSUPPORT
	}
}

func debugPrintSockaddrInet4(sa *SockaddrInet4) {
	// Write(1, []byte("  SockaddrInet4: Port="+itoa.Itoa(sa.Port)+"\n"))
	// Write(1, []byte("  SockaddrInet4: Address="+bytesToHexByteString(sa.Addr[:])+"\n"))
}

func debugPrintSockaddrInet6(sa *SockaddrInet6) {
	// Write(1, []byte("  SockaddrInet6: Port="+itoa.Itoa(sa.Port)+"\n"))
	// Write(1, []byte("  SockaddrInet6: Address="+bytesToHexByteString(sa.Addr[:])+"\n"))
}
func debugPrintSockaddr(sa Sockaddr) {
	switch sa := sa.(type) {
	case *SockaddrInet4:
		debugPrintSockaddrInet4(sa)
	case *SockaddrInet6:
		debugPrintSockaddrInet6(sa)
	}
}

func debugPrintRawSockaddrWithPortAny(rsa *RawSockaddrWithPortAny) {
	// Write(1, []byte("  RawSockaddrWithPortAny: Tag="+itoa.Itoa(int(rsa.Tag))+"\n"))
	// Write(1, []byte("  RawSockaddrWithPortAny: Octets="+bytesToHexByteString(rsa.Octets[:])+"\n"))
}

func rawWithPortToSockaddr(rsa *RawSockaddrWithPortAny) (Sockaddr, error) {
	switch rsa.Tag {
	case AF_INET:
		var sa SockaddrInet4

		// Port: native endian (matches Rust u16::from_ne_bytes)
		sa.Port = int(uint16(rsa.Octets[0]) | uint16(rsa.Octets[1])<<8)
		// IPv4 address: octs[2..6)
		copy(sa.Addr[:], rsa.Octets[2:6])

		return sa, nil

	case AF_INET6:
		var sa SockaddrInet6

		// Port: native endian
		sa.Port = int(uint16(rsa.Octets[0]) | uint16(rsa.Octets[1])<<8)

		// IPv6 address: octs[2..18)
		copy(sa.Addr[:], rsa.Octets[2:18])

		// ZoneId is not encoded in __wasi_addr_port_t
		sa.ZoneId = 0

		return sa, nil

	default:
		// Write(1, []byte("rawWithPortToSockaddr: Unknown tag="+itoa.Itoa(int(rsa.Tag))+"\n"))
		return nil, EAFNOSUPPORT
	}
}

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
	// Write(1, []byte("Socket.Socket: domain="+itoa.Itoa(domain)+", typ="+itoa.Itoa(typ)+", typ8bits="+itoa.Itoa(int(type_))+", proto="+itoa.Itoa(proto)+"\n"))
	// fmt.Sprintf("Socket.Socket: domain=%d, typ=%d, proto=%d\n", domain, typ, proto)

	var fd int32
	errno := sock_open(int32(domain), int32(type_), int32(proto), unsafe.Pointer(&fd))
	if errno != Errno(0) {
		return 0, errnoErr(errno)
	}
	return int(fd), nil
}

func setDefaultSockopts(s, family, sotype int, ipv6only bool) error {
	// Write(1, []byte("Socket.setDefaultSockopts\n"))
	return ENOSYS
}

func patchPort(rsa *RawSockaddrWithPortAny) {
	port_low, port_high := rsa.Octets[0], rsa.Octets[1]
	rsa.Octets[0] = port_high
	rsa.Octets[1] = port_low
}

func Getsockname(fd int) (Sockaddr, error) {
	// Write(1, []byte("Socket.Getsockname\n"))
	raw_sa := new(RawSockaddrWithPortAny) // zero everything
	err := sock_addr_local(int32(fd), unsafe.Pointer(raw_sa))
	if err != Errno(0) {
		return nil, err
	}
	// HACK: WASIX returns the port in little-endian order for this call, so we need to patch it
	patchPort(raw_sa)
	debugPrintRawSockaddrWithPortAny(raw_sa)
	sock_addr, err2 := rawWithPortToSockaddr(raw_sa)
	if err2 != nil {
		return nil, err2
	}
	debugPrintSockaddr(sock_addr)
	return sock_addr, nil
}

func setDefaultMulticastSockopts(s int) error {
	// Write(1, []byte("Socket.setDefaultMulticastSockopts\n"))
	return nil
}

func setDefaultListenerSockopts(s int) error {
	// Write(1, []byte("Socket.setDefaultListenerSockopts\n"))
	return nil
}

func Getpeername(fd int) (Sockaddr, error) {
	// Write(1, []byte("Socket.Getpeername\n"))
	raw_sa := new(RawSockaddrWithPortAny) // zero everything
	err := sock_addr_peer(int32(fd), unsafe.Pointer(raw_sa))
	if err != Errno(0) {
		return nil, err
	}
	patchPort(raw_sa)
	return rawWithPortToSockaddr(raw_sa)
}

func bytesToHexByteString(b []byte) string {
	const hexdigits = "0123456789abcdef"

	if len(b) == 0 {
		return ""
	}

	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hexdigits[v>>4], hexdigits[v&0x0f])
	}
	return string(out)
}

func Bind(fd int, sa Sockaddr) error {
	// Write(1, []byte("Socket.Bind\n"))
	debugPrintSockaddr(sa)
	raw_sa, err := sockaddrToRawWithPort(sa)
	if err != nil {
		return err
	}
	// size := unsafe.Sizeof(raw_sa)
	// bytes := unsafe.Slice((*byte)(unsafe.Pointer(raw_sa)), size)
	// Write(1, []byte("Sizeof(raw_sa): "+itoa.Itoa(int(size))+", Bytes: "+bytesToHexByteString(bytes)+"\n"))
	debugPrintRawSockaddrWithPortAny(raw_sa)

	sock_bind(int32(fd), unsafe.Pointer(raw_sa))

	if err != Errno(0) {
		return err
	}
	return nil
}

func StopIO(fd int) error {
	// Write(1, []byte("Socket.StopIO\n"))
	return ENOSYS
}

func Listen(fd int, backlog int) error {
	// Write(1, []byte("Socket.Listen\n"))
	errno := sock_listen(int32(fd), int32(backlog))
	if errno != Errno(0) {
		return errnoErr(errno)
	}
	return nil
}

func Accept(fd int) (int, Sockaddr, error) {
	// Write(1, []byte("Socket.Accept\n"))
	var newfd int32 = -1
	sock_addr := new(RawSockaddrWithPortAny)

	errno := sock_accept_v2(int32(fd), FDFLAG_NONBLOCK, unsafe.Pointer(&newfd), unsafe.Pointer(sock_addr))
	if errno != Errno(0) {
		return 0, nil, errnoErr(errno)
	}
	// patchPort(sock_addr)
	debugPrintRawSockaddrWithPortAny(sock_addr)
	from_addr, err := rawWithPortToSockaddr(sock_addr)
	debugPrintSockaddr(from_addr)
	if err != nil {
		return -1, nil, err
	}
	return int(newfd), from_addr, nil
}

func Connect(fd int, sa Sockaddr) error {
	// Write(1, []byte("Socket.Connect\n"))
	sz, err := sockaddrToRawWithPort(sa)
	if err != nil {
		return err
	}
	err = sock_connect(int32(fd), unsafe.Pointer(sz))
	if err != Errno(0) {
		return err
	}
	return nil
}

func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error) {
	// Write(1, []byte("Socket.Recvfrom\n"))
	raw_sa := new(RawSockaddrWithPortAny) // zero everything
	var n_int32 int32
	var flags_int32 int32
	err = sock_recv_from(int32(fd), unsafe.Pointer(&p[0]), int32(len(p)), int32(flags), unsafe.Pointer(&n_int32), unsafe.Pointer(&flags_int32), unsafe.Pointer(raw_sa))
	if err != Errno(0) {
		return 0, nil, err
	}
	patchPort(raw_sa)
	from_addr, err := rawWithPortToSockaddr(raw_sa)
	if err != nil {
		return 0, nil, err
	}
	return int(n_int32), from_addr, nil
}

func Sendto(fd int, p []byte, flags int, to Sockaddr) error {
	// Write(1, []byte("Socket.Sendto\n"))
	raw_sa, err := sockaddrToRawWithPort(to)
	if err != nil {
		return err
	}
	var n_int32 int32
	err = sock_send_to(int32(fd), unsafe.Pointer(&p[0]), int32(len(p)), int32(flags), unsafe.Pointer(&n_int32), unsafe.Pointer(raw_sa))
	if err != Errno(0) {
		return err
	}
	return nil
}

func Recvmsg(fd int, p, oob []byte, flags int) (n, oobn, recvflags int, from Sockaddr, err error) {
	// Write(1, []byte("Socket.Recvmsg\n"))
	raw_sa := new(RawSockaddrWithPortAny) // zero everything
	var n_int32 int32
	var recvflags_int32 int32
	err = sock_recv_from(int32(fd), unsafe.Pointer(&p[0]), int32(len(p)), int32(flags), unsafe.Pointer(&n_int32), unsafe.Pointer(&recvflags_int32), unsafe.Pointer(raw_sa))
	if err != Errno(0) {
		return 0, 0, 0, nil, err
	}
	from_addr, err := rawWithPortToSockaddr(raw_sa)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return int(n_int32), int(recvflags_int32), int(recvflags_int32), from_addr, nil
}

func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (n int, err error) {
	// Write(1, []byte("Socket.SendmsgN\n"))

	// Equivalent to: if (msg->msg_iov == NULL)
	if len(p) == 0 {
		return 0, EINVAL
	}

	// WASIX send flags
	var siFlags int32 = 0
	if (flags & MSG_DONTWAIT) != 0 {
		siFlags |= 1 // __WASI_SIFLAGS_SEND_DONT_WAIT
	}

	var sent int32
	var errno Errno

	if to == nil {
		// Connected socket → sock_send
		errno = sock_send(
			int32(fd),
			unsafe.Pointer(&p[0]),
			int32(len(p)),
			siFlags,
			unsafe.Pointer(&sent),
		)
	} else {
		// Send-to variant
		rawSA, err := sockaddrToRawWithPort(to)
		if err != nil {
			return 0, err
		}

		errno = sock_send_to(
			int32(fd),
			unsafe.Pointer(&p[0]),
			int32(len(p)),
			siFlags,
			unsafe.Pointer(&sent),
			unsafe.Pointer(rawSA),
		)
	}

	if errno != Errno(0) {
		return 0, errnoErr(errno)
	}

	return int(sent), nil
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	// Write(1, []byte("Socket.GetsockoptInt\n"))

	// Apply protocol → SOL_SOCKET normalization
	level, opt = normalizeSockopt(level, opt)

	if level != SOL_SOCKET {
		return 0, ENOPROTOOPT
	}

	switch opt {

	// ---------- Boolean options ----------
	case SO_ACCEPTCONN,
		SO_BROADCAST,
		SO_DONTROUTE,
		SO_NODELAY,
		SO_OOBINLINE,
		SO_V6ONLY,
		SO_REUSEPORT,
		SO_REUSE_ADDR,
		SO_MULTICAST_LOOP_V4,
		SO_MULTICAST_LOOP_V6,
		SO_KEEPALIVE:

		var on int32
		errno := sock_get_opt_flag(
			int32(fd),
			int32(opt),
			unsafe.Pointer(&on),
		)
		if errno != Errno(0) {
			return 0, errnoErr(errno)
		}

		if on != 0 {
			return 1, nil
		}
		return 0, nil

	// ---------- Size-based options ----------
	case SO_RCVBUF,
		SO_SNDBUF,
		SO_TTL,
		SO_MULTICAST_TTL_V4:

		var sz int64
		errno := sock_get_opt_size(
			int32(fd),
			int32(opt),
			unsafe.Pointer(&sz),
		)
		if errno != Errno(0) {
			return 0, errnoErr(errno)
		}

		return int(sz), nil

	// ---------- Always-zero options ----------
	case SO_ERROR,
		SO_PROTOCOL:
		return 0, nil
	}

	return 0, ENOPROTOOPT
}

func normalizeSockopt(level, opt int) (int, int) {
	// Protocol → socket-level remapping
	if level == IPPROTO_IPV6 && opt == IPV6_V6ONLY {
		return SOL_SOCKET, SO_V6ONLY
	}
	if level == IPPROTO_TCP && opt == TCP_NODELAY {
		return SOL_SOCKET, SO_NODELAY
	}
	return level, opt
}

func SetsockoptInt(fd, level, opt int, value int) error {
	// Write(1, []byte("Socket.SetsockoptInt\n"))
	level, opt = normalizeSockopt(level, opt)

	if level != SOL_SOCKET {
		return ENOSYS
	}

	switch opt {

	// ---------- Boolean options ----------
	case SO_ACCEPTCONN,
		SO_BROADCAST,
		SO_DONTROUTE,
		SO_NODELAY,
		SO_OOBINLINE,
		SO_V6ONLY,
		SO_REUSEPORT,
		SO_REUSE_ADDR,
		SO_MULTICAST_LOOP_V4,
		SO_MULTICAST_LOOP_V6,
		SO_KEEPALIVE:

		var on int32 = 0
		if value > 0 {
			on = 1
		}

		errno := sock_set_opt_flag(
			int32(fd),
			int32(opt),
			on,
		)
		if errno != Errno(0) {
			return errnoErr(errno)
		}
		return nil

	// ---------- Size-based options ----------
	case SO_RCVBUF,
		SO_SNDBUF,
		SO_TTL,
		SO_MULTICAST_TTL_V4:

		errno := sock_set_opt_size(
			int32(fd),
			int32(opt),
			int64(value),
		)
		if errno != Errno(0) {
			return errnoErr(errno)
		}
		return nil
	}

	return ENOPROTOOPT
}

func SetReadDeadline(fd int, t int64) error {
	// Write(1, []byte("Socket.SetReadDeadline\n"))
	return ENOSYS
}

func SetWriteDeadline(fd int, t int64) error {
	// Write(1, []byte("Socket.SetWriteDeadline\n"))
	return ENOSYS
}

func Shutdown(fd int, how int) error {
	// Write(1, []byte("Socket.Shutdown\n"))
	errno := sock_shutdown(int32(fd), sdflags(how))
	if errno != Errno(0) {
		return errnoErr(errno)
	}
	return nil
}

type Linger struct {
	Onoff  int32
	Linger int32
}

type wasiOptionTimestamp struct {
	Tag       wasiOptionTag
	_         byte
	Timestamp uint64
}

func SetsockoptLinger(fd, level, opt int, l *Linger) (err error) {
	// Write(1, []byte("Socket.SetsockoptLinger\n"))

	level, opt = normalizeSockopt(level, opt)

	if level != SOL_SOCKET || opt != SO_LINGER {
		return ENOPROTOOPT
	}
	if l == nil {
		return EINVAL
	}
	var tm wasiOptionTimestamp

	if l.Onoff > 0 {
		tm.Tag = wasiOptionSome
		tm.Timestamp = uint64(l.Linger) * 1_000_000_000
	} else {
		tm.Tag = wasiOptionNone
		tm.Timestamp = 0
	}

	errno := sock_set_opt_time(
		int32(fd),
		int32(opt),
		unsafe.Pointer(&tm),
	)
	if errno != Errno(0) {
		return errnoErr(errno)
	}
	return nil
}

func SetsockoptTimeval(fd, level, opt int, tv *Timeval) (err error) {
	// Write(1, []byte("Socket.SetsockoptTimeval\n"))

	level, opt = normalizeSockopt(level, opt)

	if level != SOL_SOCKET {
		return ENOPROTOOPT
	}

	switch opt {
	case SO_RCVTIMEO,
		SO_SNDTIMEO,
		SO_CONNTIMEO,
		SO_ACCPTIMEO:
		// allowed
	default:
		return ENOPROTOOPT
	}

	if tv == nil {
		return EINVAL
	}

	var tm wasiOptionTimestamp

	if tv.Sec > 0 || tv.Usec > 0 {
		tm.Tag = wasiOptionSome
		tm.Timestamp =
			uint64(tv.Sec)*1_000_000_000 +
				uint64(tv.Usec)*1_000
	} else {
		tm.Tag = wasiOptionNone
		tm.Timestamp = 0
	}

	errno := sock_set_opt_time(
		int32(fd),
		int32(opt),
		unsafe.Pointer(&tm),
	)
	if errno != Errno(0) {
		return errnoErr(errno)
	}

	return nil
}

func SetsockoptInet4Addr(fd, level, opt int, value [4]byte) (err error) {
	// Write(1, []byte("Socket.SetsockoptInet4Addr\n"))
	return SetsockoptInt(fd, level, opt, int(value[0])<<24|int(value[1])<<16|int(value[2])<<8|int(value[3]))
}

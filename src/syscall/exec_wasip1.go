// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

// Fork, exec, wait, etc.

package syscall

import (
	"internal/bytealg"
	"internal/itoa"
	"sync"
	"unsafe"
)

// ForkLock is used to synchronize creation of new file descriptors
// with fork.
//
// We want the child in a fork/exec sequence to inherit only the
// file descriptors we intend. To do that, we mark all file
// descriptors close-on-exec and then, in the child, explicitly
// unmark the ones we want the exec'ed program to keep.
// Unix doesn't make this easy: there is, in general, no way to
// allocate a new file descriptor close-on-exec. Instead you
// have to allocate the descriptor and then mark it close-on-exec.
// If a fork happens between those two events, the child's exec
// will inherit an unwanted file descriptor.
//
// This lock solves that race: the create new fd/mark close-on-exec
// operation is done holding ForkLock for reading, and the fork itself
// is done holding ForkLock for writing. At least, that's the idea.
// There are some complications.
//
// Some system calls that create new file descriptors can block
// for arbitrarily long times: open on a hung NFS server or named
// pipe, accept on a socket, and so on. We can't reasonably grab
// the lock across those operations.
//
// It is worse to inherit some file descriptors than others.
// If a non-malicious child accidentally inherits an open ordinary file,
// that's not a big deal. On the other hand, if a long-lived child
// accidentally inherits the write end of a pipe, then the reader
// of that pipe will not see EOF until that child exits, potentially
// causing the parent program to hang. This is a common problem
// in threaded C programs that use popen.
//
// Luckily, the file descriptors that are most important not to
// inherit are not the ones that can take an arbitrarily long time
// to create: pipe returns instantly, and the net package uses
// non-blocking I/O to accept on a listening socket.
// The rules for which file descriptor-creating operations use the
// ForkLock are as follows:
//
//   - [Pipe]. Use pipe2 if available. Otherwise, does not block,
//     so use ForkLock.
//   - [Socket]. Use SOCK_CLOEXEC if available. Otherwise, does not
//     block, so use ForkLock.
//   - [Open]. Use [O_CLOEXEC] if available. Otherwise, may block,
//     so live with the race.
//   - [Dup]. Use [F_DUPFD_CLOEXEC] or dup3 if available. Otherwise,
//     does not block, so use ForkLock.
var ForkLock sync.RWMutex

// StringSlicePtr converts a slice of strings to a slice of pointers
// to NUL-terminated byte arrays. If any string contains a NUL byte
// this function panics instead of returning an error.
//
// Deprecated: Use [SlicePtrFromStrings] instead.
func StringSlicePtr(ss []string) []*byte {
	bb := make([]*byte, len(ss)+1)
	for i := 0; i < len(ss); i++ {
		bb[i] = StringBytePtr(ss[i])
	}
	bb[len(ss)] = nil
	return bb
}

// SlicePtrFromStrings converts a slice of strings to a slice of
// pointers to NUL-terminated byte arrays. If any string contains
// a NUL byte, it returns (nil, [EINVAL]).
func SlicePtrFromStrings(ss []string) ([]*byte, error) {
	n := 0
	for _, s := range ss {
		if bytealg.IndexByteString(s, 0) != -1 {
			return nil, EINVAL
		}
		n += len(s) + 1 // +1 for NUL
	}
	bb := make([]*byte, len(ss)+1)
	b := make([]byte, n)
	n = 0
	for i, s := range ss {
		bb[i] = &b[n]
		copy(b[n:], s)
		n += len(s) + 1
	}
	return bb, nil
}

// Credential holds user and group identities to be assumed
// by a child process started by [StartProcess].
type Credential struct {
	Uid         uint32   // User ID.
	Gid         uint32   // Group ID.
	Groups      []uint32 // Supplementary group IDs.
	NoSetGroups bool     // If true, don't set supplementary groups
}

var zeroProcAttr ProcAttr
var zeroSysProcAttr SysProcAttr

// Implemented in runtime package.
func runtime_BeforeExec()
func runtime_AfterExec()

// JoinStrings joins the arguments into a single string, without using
// any utility functions from the standard library.
// separated by \n.
func JoinStrings(strings []string, separator string) string {
	joined := ""
	for _, str := range strings {
		joined += str + separator
	}
	return joined
}

// StartProcess wraps [ForkExec] for package os.
func StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error) {
	pid, err = ForkExec(argv0, argv, attr)
	return pid, 0, err
}

//go:wasmimport wasix_32v1 proc_spawn2
//go:noescape
func proc_spawn2(
	name uintptr,
	nameLen int32,
	args uintptr,
	argsLen int32,
	envs uintptr,
	envsLen int32,
	fdOps uintptr,
	fdOpsLen int32,
	signalActions uintptr,
	signalActionsLen int32,
	searchPath bool,
	path uintptr,
	pathLen int32,
	ret *int32,
) Errno

// Combination of fork and exec, careful to be thread safe.
func ForkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error) {
	argv0p, err := BytePtrFromString(argv0)
	if err != nil {
		return 0, err
	}
	argvJoined := JoinStrings(argv, "\n")
	argvp, err := BytePtrFromString(argvJoined)
	if err != nil {
		return 0, err
	}
	envvJoined := JoinStrings(attr.Env, "\n")
	envvp, err := BytePtrFromString(envvJoined)
	if err != nil {
		return 0, err
	}

	var path = "/bin"
	pathp, err := BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	ret := make([]int32, 1)
	// var retPid int32

	Write(1, []byte("proc_spawn2\n"))
	Write(1, []byte(argv0))
	Write(1, []byte(argvJoined))
	Write(1, []byte(envvJoined))
	Write(1, []byte(path))
	Write(1, []byte("Files num "+itoa.Itoa(len(attr.Files))))
	// fmt.Println("proc_spawn2", argv0p, argvp, envvp, pathp, ret, argvJoined, envvJoined, path)

	runtime_BeforeExec()

	err = proc_spawn2(
		uintptr(unsafe.Pointer(argv0p)),
		int32(len(argv0)),
		uintptr(unsafe.Pointer(argvp)),
		int32(len(argvJoined)),
		uintptr(unsafe.Pointer(envvp)),
		int32(len(envvJoined)),
		0, // <- IMPLEMENT THIS
		0, // <- IMPLEMENT THIS
		0,
		0,
		true,
		uintptr(unsafe.Pointer(pathp)),
		int32(len(path)),
		&ret[0],
	)
	runtime_AfterExec()
	if err == Errno(0) {
		return int(ret[0]), nil
	}
	return 0, err
}

// Exec invokes the execve(2) system call.
func Exec(argv0 string, argv []string, envv []string) (err error) {
	argv0p, err := BytePtrFromString(argv0)
	if err != nil {
		return err
	}
	argvJoined := JoinStrings(argv, "\n")
	argvp, err := BytePtrFromString(argvJoined)
	if err != nil {
		return err
	}
	envvJoined := JoinStrings(envv, "\n")
	envvp, err := BytePtrFromString(envvJoined)
	if err != nil {
		return err
	}
	runtime_BeforeExec()
	err = proc_spawn2(
		uintptr(unsafe.Pointer(argv0p)),
		int32(len(argv0)),
		uintptr(unsafe.Pointer(argvp)),
		int32(len(argvJoined)),
		uintptr(unsafe.Pointer(envvp)),
		int32(len(envvJoined)),
		0,
		0,
		0,
		0,
		false,
		uintptr(unsafe.Pointer(argv0p)),
		int32(len(argv0)),
		nil,
	)
	runtime_AfterExec()
	if err != nil {
		return err
	}
	return nil
}

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

package filelock

type lockType int8

const (
	readLock = iota + 1
	writeLock
)

func lock(f File, lt lockType) error {
	return nil
	// return &fs.PathError{
	// 	Op:   lt.String(),
	// 	Path: f.Name(),
	// 	Err:  errors.ErrUnsupported,
	// }
}

func unlock(f File) error {
	return nil
	// return &fs.PathError{
	// 	Op:   "Unlock",
	// 	Path: f.Name(),
	// 	Err:  errors.ErrUnsupported,
	// }
}

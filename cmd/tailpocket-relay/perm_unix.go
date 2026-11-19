//go:build !windows

package main

import (
	"os"
	"syscall"
)

// othersCanRead reports whether group or other users may read path.
func othersCanRead(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm()&0o044 != 0
}

// openFileLimit is the current open-file limit. Go already raised the soft
// limit at start-up (src/syscall/rlimit.go), so this is what the relay has.
func openFileLimit() (uint64, bool) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, false
	}
	return uint64(rl.Cur), true
}

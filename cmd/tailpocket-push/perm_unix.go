//go:build !windows

package main

import "os"

// othersCanRead reports whether group or other users may read path.
func othersCanRead(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm()&0o044 != 0
}

// syncDir makes a rename in dir last across a crash.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

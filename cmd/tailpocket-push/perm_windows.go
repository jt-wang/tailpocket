package main

// othersCanRead: file modes do not say who can read a file on Windows.
func othersCanRead(string) bool { return false }

// syncDir: directories cannot be synced on Windows.
func syncDir(string) {}

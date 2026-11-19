package main

// othersCanRead: file modes do not say who can read a file on Windows.
func othersCanRead(string) bool { return false }

// openFileLimit: not checked on Windows.
func openFileLimit() (uint64, bool) { return 0, false }

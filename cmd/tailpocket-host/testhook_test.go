package main

import "github.com/jt-wang/tailpocket/internal/testhook"

func init() { testhook.LoopbackRoutes = true } // host and phone run on one machine

// Package testhook holds switches only this module's tests and test tools set. Apps cannot import
// an internal package, so a release build of a phone library always runs with them off.
package testhook

import "sync/atomic"

// LoopbackRoutes lets lan routes name loopback addresses (tests run host and phone on one machine).
var LoopbackRoutes bool

// NoUpgrade keeps a phone's session on the route that worked (no connectphone Session.upgrade), so a
// test can hold it on the relay.
var NoUpgrade atomic.Bool

// TailcatStarts counts every Tailcat server and client this module creates, host and phone side, so
// a test can show a configuration without Tailcat creates none.
var TailcatStarts atomic.Int64

// LastRoute, when set, replaces how long a phone's Dial waits on its last route (connectphone).
var LastRoute atomic.Int64 // time.Duration

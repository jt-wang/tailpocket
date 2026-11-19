// Package testhook holds switches only this module's tests and test tools set. Apps cannot import
// an internal package, so a release build of a phone library always runs with them off.
package testhook

// LoopbackRoutes lets lan routes name loopback addresses (tests run host and phone on one machine).
var LoopbackRoutes bool

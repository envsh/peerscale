// Package simlibp2p provides helpers for simulating the libp2p protocol
// stack.
//
// This is a trimmed stub: the upstream package depends on the QUIC/WebRTC
// transport stack which is removed from this fork. It exists only so that
// `go mod tidy` can resolve the import path referenced by the test files of
// go-libp2p-pubsub. It is never compiled into a binary.
package simlibp2p
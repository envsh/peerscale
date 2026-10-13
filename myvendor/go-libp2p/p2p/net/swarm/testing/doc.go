// Package testing provides libp2p swarm test helpers.
//
// This is a trimmed stub: the upstream package depends on the QUIC transport
// stack which is removed from this fork. It exists only so that `go mod tidy`
// can resolve the import path referenced by the test files of go-libp2p-kad-dht
// and go-libp2p-pubsub. It is never compiled into a binary.
package testing
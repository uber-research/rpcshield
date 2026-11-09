// Command genericgrpcthrift is a fixture that calls into package pb (a stand-in for
// protoc-gen-go-grpc/Apache-Thrift-generated code) the way real generated-code callers do:
// package-qualified for server registration, via a local client value for outbound calls. See
// pb's doc comment for why the generated shapes live in a separate package.
package main

import (
	"context"

	"google.golang.org/grpc"

	"github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift/pb"
)

// callFoo exercises pb.FooClient.Foo as an outbound call site.
func callFoo(c *pb.FooClient) error {
	return c.Foo(context.Background())
}

// fooServerImpl implements pb.FooServer, the shape findGenericGRPCServer should detect via the
// pb.RegisterFooServer call below.
type fooServerImpl struct{}

func (fooServerImpl) Foo(context.Context) error { return nil }

// setupGRPCServer registers fooServerImpl, the call site findGenericGRPCServer should detect.
func setupGRPCServer() {
	s := grpc.NewServer()
	pb.RegisterFooServer(s, fooServerImpl{})
}

// bazPart and quxPart each implement one method of pb.BazServer. Neither implements the whole
// interface, and the composite handler built from them only ever has the interface as its static
// type outside newBazServer, so the implements-based rule cannot attribute their methods to a
// server. The registration-rooted rule follows srv in setupCompositeServer to its single
// assignment, then newBazServer's return statement, and finds them.
type bazPart struct{}

func (bazPart) Baz(context.Context) error { return nil }

type quxPart struct{}

func (*quxPart) Qux(context.Context) error { return nil }

// newBazServer assembles a handler from bazPart and quxPart, the way services compose a server
// from per-feature partial implementations, and returns it as the server interface, the
// idiomatic constructor shape.
func newBazServer() pb.BazServer {
	return struct {
		bazPart
		*quxPart
	}{bazPart{}, &quxPart{}}
}

// setupCompositeServer registers the handler newBazServer builds through an interface-typed local
// variable.
func setupCompositeServer() {
	s := grpc.NewServer()
	srv := newBazServer()
	pb.RegisterBazServer(s, srv)
}

// callBar exercises pb.BarClient.Bar as an outbound call site.
func callBar(c *pb.BarClient) error {
	return c.Bar(context.Background())
}

// barHandlerImpl implements pb.BarHandler, the shape findGenericThriftServer should detect via
// the pb.NewBarProcessor call below.
type barHandlerImpl struct{}

func (barHandlerImpl) Bar(context.Context) error { return nil }

// setupThriftServer constructs a processor for barHandlerImpl, the call site
// findGenericThriftServer should detect.
func setupThriftServer() {
	pb.NewBarProcessor(barHandlerImpl{})
}

func main() {}

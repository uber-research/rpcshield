# finder: where a service receives and makes RPCs

`finder` locates the two kinds of program points the rest of the analyzer works between:

- **Inbound points** (`Finder.Inbound`): the handler methods a server in this binary dispatches
  to. Each becomes a root of the call graph, and every finding is reported against one.
- **Outbound points** (`Finder.Outbound`): the call expressions that send a request to another
  service. Each becomes a sink; a path from an inbound to an outbound is what gets classified
  fail-open or fail-close.

Both are found from syntax and types (`go/ast`, `go/types`, as loaded by `go/packages`), before any
SSA or call graph exists. The one exception is HTTP inbound detection, which reads SSA because
routes are registered by value, not by type. This document explains the RPC stacks the finder
recognizes, the rules it applies, what each rule gets right and misses, and how to add a new stack.

## 1. The RPC stack, and what is recognizable in it

An RPC call in Go goes through four layers. Knowing which layer a name belongs to tells you what
the finder can anchor on.

| layer | examples | what it contributes |
|---|---|---|
| IDL and wire encoding | Protobuf, Thrift | the service definition: a list of methods with request and response types |
| code generator | `protoc-gen-go-grpc`, `protoc-gen-yarpc-go`, `thriftrw` + its YARPC plugin, `thriftrw-plugin-tchannel`, Apache Thrift's Go generator | Go code with a fixed, documented shape: a server interface, a client type, a registration function, a processor or procedure builder |
| RPC framework | `google.golang.org/grpc`, `go.uber.org/yarpc`, `github.com/uber/tchannel-go`, Apache Thrift's `lib/go/thrift`, `net/rpc`, `ttrpc` | the server that dispatches to handlers and the client that sends requests; the framework's own types appear in the generated signatures |
| transport | HTTP/2 (gRPC), TChannel, HTTP/1.1 | invisible to the finder, except that HTTP/1.1 is also used directly, without an IDL (section 1.3) |

Dependency injection (`go.uber.org/fx`, `dig`) is not part of the stack; it is how handlers reach
registration functions in many services, so the finder has to see through it (section 2.4).

### 1.1 Generated code is the anchor

Every generator emits two things per service that the finder can recognize by their *types*, with
no reliance on names:

- a **server interface** `I` listing the service's methods, and a **registration function** (the
  *registrar*) that takes a value of type `I` and hands it to a server. The registrar's signature
  involves a framework type, which identifies the stack:

  | stack | registrar shape | handler parameter |
  |---|---|---|
  | gRPC (`protoc-gen-go-grpc`) | `func RegisterXServer(s grpc.ServiceRegistrar, srv XServer)` (older: `s *grpc.Server`) | second |
  | YARPC over Protobuf (`protoc-gen-yarpc-go`) | `func BuildXYARPCProcedures(server XYARPCServer, opts ...) []transport.Procedure` | first |
  | YARPC over Thrift (`thriftrw-plugin-yarpc`) | `func New(impl Interface, opts ...thrift.RegisterOption) []transport.Procedure` in package `…/xserver` | first |
  | Thrift over TChannel (`thriftrw-plugin-tchannel`) | `func NewTChanXServer(handler TChanX) thrift.TChanServer` | first |
  | Apache Thrift | `func NewXProcessor(handler X) *XProcessor`, where `*XProcessor` implements `thrift.TProcessor` | first |

  YARPC's generators also emit an **fx registrar**: `NewFxXYARPCProcedures()` returns a function
  whose parameter struct has a field of type `XYARPCServer`; fx fills that field by type.

- a **client type** whose methods send requests. A call of one of those methods is an outbound
  point. The client is recognizable by what it holds:

  | stack | client shape |
  |---|---|
  | gRPC | unexported struct with a `grpc.ClientConnInterface` (or `*grpc.ClientConn`) field, behind the exported `XClient` interface |
  | YARPC over Protobuf | `XYARPCClient` interface in a `gogoproto/…` package |
  | YARPC over Thrift | `Interface` in a `thriftrw/…/xclient` package |
  | Thrift over TChannel | `TChanX` in a `thriftrw/…` package (the same interface the server implements) |
  | Apache Thrift | struct with a `thrift.TClient` field |

Generated files carry a marker comment before the package clause: `// Code generated … DO NOT
EDIT.` (the Go convention, sometimes split over two lines) or `// @generated` (thriftrw, YARPC).
The finder uses the marker to tell generated functions from hand-written ones.

### 1.2 Server versus client

The two sides are told apart by their anchor, never by naming:

- **Server side**: a value is handed to a registrar. The handler type is whatever that value's
  type is. Interfaces such as `TChanX` or Apache Thrift's `X` are used on both sides; the
  generated client also implements them. What makes a type a handler is being registered, and
  methods declared in generated files (client stubs, `UnimplementedXServer` defaults, adapters)
  are never handlers.
- **Client side**: a method is called on a client type. The generated client's methods are the
  service's operations; the stub bodies call a send primitive (`ClientConn.Invoke`, the YARPC
  encoding client's `Call`, `TClient.Call`). Hand-written code never calls the primitive
  directly, so the finder stops at the generated client method.

### 1.3 HTTP

HTTP/1.1 is the transport under gRPC, but it is also used on its own, without an IDL or generated
code. The finder treats it as a stack of its own with weaker anchors:

- **Inbound**: a route registration on a router value: `net/http.ServeMux.Handle/HandleFunc`,
  `gorilla/mux.Router.HandleFunc`, `gin.Engine.GET/POST/…`. The handler is the function value
  passed in. Because the router is a value and the handler is a closure or a method value, this
  detection runs on SSA (`finder/http`), where values are explicit.
- **Outbound**: a call of `Get`, `Post`, `PostForm`, `Do` or `Head` on `net/http.Client`, or on a
  type listed in `config.Config.AdditionalHTTPClientTypes` (a company's own HTTP client wrapper).
  There is no generated client to tell an RPC from a download, so the method-name allowlist is
  the rule.

### 1.4 Not an RPC stack

Several things look like RPCs and are deliberately not treated as such here: SDK clients that wrap
RPC inside hand-written code (etcd `clientv3`, a company's storage or config clients), with the
one exception of the Cadence workflow client (`go.uber.org/cadence/client.Client`), which has a
fixed, well-known shape; Kafka consumers (detection exists but is disabled: consumers are
expected to fail close so the broker retries); `net/rpc`, whose `Register(rcvr any)` carries no
server interface to select methods from; and `ttrpc`, whose generated
`RegisterXService(*ttrpc.Server, XService)` is a registrar shape not yet in the table (section 4.1
is how to add it).

## 2. Inbound detection

`Finder.Inbound` runs the rules below and unions their results, keyed by the handler's
`*types.Func`. Every inbound carries the handler's package and function, an endpoint type (`grpc`,
`thrift`, `tchannel`, `http`) and a canonical name `<service>__<method>` in lower case
(`canonicalEndpoint`), where `<service>` comes from the generated package when it follows the
gogoproto/thriftrw layout (`canonicalServiceName`), and is the interface's package path otherwise.

### 2.1 Scope: the codebase

A binary links hundreds of packages that register handlers for their own purposes (health,
reflection, a dependency's internal bridge server). Reporting those to a service owner is not
actionable, and a handler never reached from this program's `main` has no call-graph node, which
the RTA builder treats as an error. Inbound detection is therefore scoped to the **codebase**
(`finder/types.Codebase`): the packages whose import path shares the entry package's path two
levels up (`a/b/c/cmd/svc` → `a/b/c`), plus `KeepIBPkgs`, minus `config.Config.InfraPkgPrefixes`
(packages owned by platform teams and linked into nearly every binary), and, when
`config.Config.CodebasePkgPrefix` is set, only packages under that prefix.

### 2.2 Rule: implements a server interface (YARPC)

The original rule, for YARPC-generated code, whose packages have a fixed layout (`gogoproto/<idl
path>` and `thriftrw/<idl path>/<service>server`):

1. Collect every server interface the program uses: a type named `…YARPCServer` in a `gogoproto/`
   package, or `Interface` in a `thriftrw/…server` package (`serverInterfaces`). Zero-method
   interfaces are skipped.
2. For every struct type declared in a codebase package, check `types.Implements` against each
   interface, as a value and as a pointer. The struct's methods that implement the interface
   become inbounds (`implFuncsFor`); a method promoted from an embedded *interface* field is
   skipped, since no code is behind it (`isAbstractPromotedMethod`).
3. When several structs implement one interface, keep the ones in a package with a `handler`
   path element if any exist (`filterImplStructs`). This is the only name-based step in inbound
   detection, and exists because mocks, gateways and decorators also implement the interface.

What it gets right: the common case of one handler struct per service, with no need to find the
registration. What it misses: a handler composed from partial implementations (none implements
the whole interface), a handler type declared outside the two-levels-up prefix, a server
interface the program names only through generated code (the rule looks at *uses*, and a
generated fx module may be the only user); and it has no way to tell a registered implementation
from an unregistered one, hence step 3.

### 2.3 Rule: registration call with a direct argument (TChannel, generic gRPC, Apache Thrift)

For stacks without a package-layout convention, the rules root at the registration call and read
the handler argument's static type:

- **TChannel**: calls of `NewTChan…` in `thriftrw/` packages (`findTChanServer`).
- **gRPC** (`protoc-gen-go-grpc`) and **Apache Thrift**, under
  `config.Config.EnableGenericGRPCThriftDetection`: calls of a `Register…Server` function whose
  package imports `google.golang.org/grpc`, and of a `New…Processor` function whose package
  imports Apache Thrift (`findGenericGRPCServer`, `findGenericThriftServer`). When the argument's
  static type is an interface and the argument is a constructor call, the constructor's first
  struct-typed return statement gives the concrete type (`resolveConcreteImplType`).

What they miss: an argument that is a variable or a field, a constructor behind another
constructor, and handlers that arrive through fx.

### 2.4 Rule: registration-rooted, following values (`registration*.go`)

On by default (`config.Config.DisableRegistrationInboundDetection` turns it off). This rule
generalizes 2.3 to every stack in section 1.1 and follows the registered value where the syntax
shows it. It adds to the handlers found by 2.2 and 2.3; an existing entry is never changed.

The code is split by concern: `registration_shape.go` recognizes generated files and registrar
signatures; `registration_flows.go` gathers, in one pass over the program, which static types
reach each interface type and which expressions are stored into each struct field;
`registration_resolve.go` resolves a registered value to concrete types and an interface method
to the method that runs; `registration.go` holds the index, the site discovery and the
conversion to inbound points. Every function that inspects syntax or types carries examples of
the source it accepts and rejects, and of what it returns for each.

1. **Registrars** are generated functions whose signature has one of the shapes in the table of
   section 1.1 (`registrarShapeOf`). Recognition is by the framework types in the signature,
   plus for YARPC the import of `go.uber.org/yarpc/encoding/protobuf` (or `…/thrift`, including
   their `v2` subpackages) that decides the endpoint type. A hand-written function with the same
   shape is not a registrar. The handler parameter's type is the server interface `I`.
2. **Registration sites** are: a call of a registrar; a use of a registrar as a function value
   (`fx.Provide(xserver.New)`), where the handler arrives by type; and a call, from hand-written
   code, of a generated fx registrar (`collectFxRegistrar`), likewise.
3. The **registered value** is resolved to concrete types (`exprTypes`):
   - a non-interface expression is its static type;
   - a call of a statically known, non-generic function with unnamed results is resolved through
     the function's `return` statements (`returnedTypes`), including a two-result constructor
     `h, err := newHandler()`;
   - a local variable with exactly one assignment and no address taken is resolved through that
     assignment (`localVarTypes`);
   - a struct field is resolved through every expression stored into it, by composite literal or
     assignment (`fieldTypes`), unless the field's address is taken or its struct embeds `fx.In`
     or `dig.In`, in which case fx fills it and the stores are not the whole story;
   - anything else, and the by-type cases of step 2, use **type-keyed flows**: the index records,
     for every interface type, the static types of the expressions used where that interface is
     expected (arguments, returns, assignments, composite literals, conversions,
     `fx.Annotate(f, fx.As(new(I)))`), and follows them to non-interface types (`concreteTypes`).
     `var _ I = (*T)(nil)` is a compile-time assertion, not a flow.
4. **Handlers** are `I`'s methods selected from the registered type's method set
   (`resolveMethod`). A method promoted from an embedded interface field is resolved through the
   values of that field, so a decorator `type quota struct{ pb.KVServer }` yields its own `Put`
   and the inner type's `Get`. Methods declared in generated files are skipped.
5. A handler is kept if its registration site or the handler itself is in the codebase.

Measured on 44 services with a reviewed ground truth (21 open-source gRPC/Thrift services, 23
YARPC services), adding this rule changed no existing inbound or outbound and raised inbound
recall from 0.50 to 0.88 (open source) and from 0.63 to 0.84 (YARPC; 1.00 of the services' own
handlers) at precision 0.98 and 0.99. The example app `exampleapps/outbounds/genericgrpcthrift`
has a handler only this rule finds (`setupCompositeServer`), and `finder/inbound_test.go` checks
both the default and the disabled configuration against it.

What it still misses: `net/rpc` (no server interface) and `ttrpc` (shape not in the table); an embedded
library server (m3's etcd) whose handlers are outside the codebase; and, in the other direction, a
registration in linked code that only another binary runs (buildkit's `session/filesync`): types
cannot see that, only reachability from `main` can.

### 2.5 Rule: HTTP routes (`finder/http`)

Runs on SSA. Each `MuxProvider` (gorilla, `net/http.ServeMux`, gin) matches the creation of a
router and the registration calls on it, and turns each registered handler function into an
inbound of type `http`. A handler registered under several routes is one inbound with
`AlsoServedAt` listing the other routes.

## 3. Outbound detection

`Finder.Outbound` walks every call expression in codebase packages (`CodebasePkgPrefix`) whose
callee is a method, takes the receiver's named type, and classifies it:

| receiver type | rule | endpoint type |
|---|---|---|
| `…YARPCClient` in `gogoproto/…`; `Interface` in `thriftrw/…client`; `TChan…` (not `…Server`) in `thriftrw/…` | YARPC client, service from the generated package (`gogoprotoThriftOutbound`) | `grpc` / `thrift` |
| struct (or the interface it backs) with a `grpc.ClientConnInterface`, `*grpc.ClientConn` or `thrift.TClient` field, under `EnableGenericGRPCThriftDetection` | generic client (`genericGRPCThriftOutbound`); the receiver interface is resolved to the struct in the same generated package (`resolveConcreteClientType`) | `grpc` / `thrift` |
| `go.uber.org/cadence/client.Client` | Cadence workflow client | `cadence` |
| `net/http.Client` or an `AdditionalHTTPClientTypes` entry, method name containing `Get`, `Post`, `PostForm`, `Do` or `Head` | HTTP client | `http` |

Every call of a client method is an outbound, including a call in a package of the service that
wraps the client: the path analysis attributes findings to the call site.

### 3.1 Which service is called

The target service is needed to decide whether a dependency is critical. `ServiceMapper.InferService`
tries, in order: a fixed mapping for well-known clients (Cadence); a mapping from client type to
service built by scanning fx constructors (`servicemapping.FxScanner`, which reads the service
name out of the `yarpc.ClientConfig("name")` call in each generated client constructor); and
finally name matching between the client's
package path and the known service names (`nameMatch`, edit distance). A call whose service cannot
be inferred is counted in `Outbound`'s second result and dropped.

### 3.2 What outbound detection misses

Calls through the service's own interfaces or function values (the receiver type is not a
client), SDK clients that are not in the table (section 1.4), and transport primitives called
directly (`http.RoundTripper.RoundTrip`, `net/rpc.Client.Call`).

## 4. Extending the finder

### 4.1 A new RPC stack with generated code

Add its registrar shape to `registrarShapeOf` in `registration_shape.go`: match the framework types
that appear in the signature (use `isNamedType` with the framework's import path; `stripVendor`
handles vendoring), return the handler parameter's index and the endpoint type, and add the
endpoint type to `finder/types/endpointtype.go` if it is new. Everything else (sites, value
resolution, method selection, scoping) is shared. Add a case to `TestRegisteredHandlers_*` in
`registration_test.go`: the tests type-check small in-memory programs that declare the framework
types themselves, so no dependency is needed.

For the client side, add a predicate like `isGenericGRPCClient` in `outbound.go`, keyed on a
field type the generated client holds or a framework type in its signature, and a case in
`Finder.Outbound`'s switch. If the stack has a package layout from which the service name can be
read, extend `canonicalServiceName`; otherwise name the endpoint by the client's package path as
`genericGRPCThriftOutbound` does.

### 4.2 A new HTTP router

Implement `finder/http.MuxProvider` (match the router type, its creation, and the registration
calls that return inbounds) and add it to the provider list in `Finder.Inbound`. `gin.go` is the
smallest example.

### 4.3 A company's own wrappers

Hand-written clients that wrap a stack (an internal HTTP client, a storage SDK) are not
generated, so no shape identifies them. Use `config.Config.AdditionalHTTPClientTypes` for HTTP
wrappers; for anything else, prefer a small library model (a fixed list of `pkg.Type.Method`
operations) over a name pattern, and record where the list came from.

### 4.4 Rules of the house

- Anchor on types the generator or framework guarantees, not on identifiers people choose. The
  remaining name-based steps (`filterImplStructs`, the HTTP method allowlist, `nameMatch`) are the
  parts most likely to be wrong on a new codebase.
- A rule that adds inbounds must not change existing ones: new rules union into the result keyed
  by `*types.Func`, as `registrationInbounds` does.
- Every inbound must be reachable from the binary's `main` in the call graph, or the RTA builder
  reports it as an error; this is why scoping (section 2.1) is not optional.
- Measure before and after on `pipeline_evaluation_scripts/` (see `CLAUDE.md`): a change to the
  finder is complete when the sweep shows no lost inbound or outbound and the added ones have
  been checked against the source.

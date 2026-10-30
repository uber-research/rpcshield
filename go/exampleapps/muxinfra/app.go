package main

import (
	"net/http"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Home"))
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Ping"))
}

// notify has a non-handler signature, so it never resolves to a handler.
func notify() {}

// wrapNotify mirrors gin.WrapF(pprof.Index): its argument parses fine as a
// function object but is not a handler, so the wrapping call yields candidates
// that are all empty and the parser must fall through instead of erroring.
func wrapNotify(f func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f() })
}

// appHandler is a codebase implementation of http.Handler, reachable only
// through the interface when a handler is registered as an interface-typed
// method value.
type appHandler struct{}

func (appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

// embedHandler also satisfies http.Handler, but through a promoted stdlib
// method: its ServeHTTP is owned by net/http, which ships without loaded
// source, so it must be filtered out rather than reported as an inbound.
type embedHandler struct {
	http.HandlerFunc
}

// params holds an interface-typed handler, mirroring infra structs whose
// handler field is an http.Handler.
type params struct {
	HTTPHandler http.Handler
}

// group holds the route-registration methods. It mirrors real frameworks (e.g.
// gin, whose verb methods live on an embedded *gin.RouterGroup) where the
// registration methods are promoted from an embedded sub-struct. A call on the
// outer router is therefore lowered by the compiler into a call on a
// field-addressed inner value.
type group struct{}

// HandleFunc registers a plain function handler.
func (g *group) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {}

// Handle takes an interface, mirroring net/http.ServeMux.Handle: passing an
// http.HandlerFunc-boxed function makes the SSA arg an *ssa.MakeInterface.
func (g *group) Handle(pattern string, h http.Handler) {}

// router embeds group by value, so router.HandleFunc(...) is promoted to
// (&router.group).HandleFunc(...). The receiver is a field-addressed *group — a
// router-typed value derived from the original router whose referrer is the
// registration call. This is the exact shape the value-following logic handles.
type router struct {
	group
}

func newRouter() *router {
	return &router{}
}

// setupRoutes registers handlers through the embedded (promoted) group methods.
func setupRoutes() *router {
	r := newRouter()

	// Promoted registration -> exercises router-value-following (the receiver is
	// a derived *group value reached via a FieldAddr on the router).
	r.HandleFunc("/promoted", homeHandler)

	// Interface-boxed handler -> exercises the ssa.MakeInterface case in the
	// handler parser (http.HandlerFunc(fn) boxed to http.Handler).
	r.Handle("/boxed", http.HandlerFunc(pingHandler))

	// Wrapped non-handler argument -> exercises the fall-through to the
	// "call itself makes a handler" heuristic when every candidate is empty.
	r.Handle("/wrapped", wrapNotify(notify))

	// Method value on a concrete source-less type (*http.ServeMux) -> must be
	// skipped rather than recorded as a phantom inbound.
	mux := http.NewServeMux()
	r.HandleFunc("/sourceless", mux.ServeHTTP)

	// Method value on an interface-typed field -> the leaf resolves to
	// net/http's abstract Handler.ServeHTTP, so the parser must resolve it to
	// the concrete codebase implementations instead.
	p := params{HTTPHandler: appHandler{}}
	r.HandleFunc("/ifacevalue", p.HTTPHandler.ServeHTTP)

	var _ http.Handler = embedHandler{}

	return r
}

func main() {
	_ = setupRoutes()
}

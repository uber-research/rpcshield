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

func wrapLogger(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r)
	}
}

// addMoreRoutes exercises delegation: the mux is passed into another function
// that registers additional routes on it.
func addMoreRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/more/ping", pingHandler)
}

func setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Plain function handler.
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/ping", pingHandler)

	// Closure handler.
	mux.HandleFunc("/closure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Closure"))
	})

	// Go 1.22 method+path pattern (still a constant string).
	mux.HandleFunc("GET /items", pingHandler)

	// Handle with an http.HandlerFunc-boxed function (goes through MakeInterface).
	mux.Handle("/wrapped", http.HandlerFunc(wrapLogger(homeHandler)))

	// Delegation.
	addMoreRoutes(mux)

	return mux
}

func main() {
	mux := setupRoutes()
	http.ListenAndServe(":8080", mux)
}

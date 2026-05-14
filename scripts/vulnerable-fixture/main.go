package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body><a href="/admin">admin</a><script src="/static/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "default admin portal")
	})
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		fmt.Fprintf(w, `{"query":%q,"warning":"unsanitized reflected parameter"}`, r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintln(w, `const apiKey = "AKIAIOSFODNN7EXAMPLE"; fetch("/api/search?q=test");`)
	})
	addr := first(os.Getenv("NOX_FIXTURE_ADDR"), "127.0.0.1:18081")
	fmt.Println("fixture listening on http://" + addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func first(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

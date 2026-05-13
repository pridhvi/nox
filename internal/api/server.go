package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Config struct {
	Host string
	Port int
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/tools", s.tools)
	mux.Handle("/", http.FileServer(http.Dir("web/dist")))

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("NOX listening on http://%s\n", server.Addr)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) tools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, []map[string]string{})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

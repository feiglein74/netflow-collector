package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"netflow-collector/internal/resolver"
	"netflow-collector/internal/store"
)

// Server ist der HTTP API Server
type Server struct {
	server   *http.Server
	handlers *Handlers
	port     int
}

// NewServer erstellt einen neuen API Server
func NewServer(flowStore *store.FlowStore, port int) *Server {
	return NewServerWithResolver(flowStore, port, nil)
}

// NewServerWithResolver erstellt einen neuen API Server mit DNS-Resolver
func NewServerWithResolver(flowStore *store.FlowStore, port int, res *resolver.Resolver) *Server {
	handlers := NewHandlersWithResolver(flowStore, res)

	mux := http.NewServeMux()

	// API v1 Endpoints
	mux.HandleFunc("/api/v1/sankey", corsMiddleware(handlers.HandleSankey))
	mux.HandleFunc("/api/v1/flows", corsMiddleware(handlers.HandleFlows))
	mux.HandleFunc("/api/v1/stats", corsMiddleware(handlers.HandleStats))
	mux.HandleFunc("/api/v1/interfaces", corsMiddleware(handlers.HandleInterfaces))

	// Health Check
	mux.HandleFunc("/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		server:   server,
		handlers: handlers,
		port:     port,
	}
}

// Start startet den API Server in einer Goroutine
func (s *Server) Start() error {
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("API Server Fehler: %v\n", err)
		}
	}()
	return nil
}

// Stop stoppt den API Server ordnungsgemäß
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// Port gibt den konfigurierten Port zurück
func (s *Server) Port() int {
	return s.port
}

// corsMiddleware fügt CORS-Header für Cross-Origin-Anfragen hinzu
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Alle Origins für lokale Entwicklung erlauben
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")

		// Preflight-Anfragen behandeln
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

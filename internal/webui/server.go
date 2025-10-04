package webui

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cneate93/vne/internal/report"
)

//go:embed index.html static/*
var content embed.FS

type RunRequest struct {
	Scan   bool   `json:"scan"`
	Target string `json:"target"`
}

type RunFunc func(context.Context, RunRequest) (report.Results, error)

type Server struct {
	runner RunFunc
	mux    *http.ServeMux

	mu    sync.Mutex
	state runState
	files http.Handler
}

type runState struct {
	phase   string
	percent float64
	message string
	running bool
	results *report.Results
}

func NewServer(runner RunFunc) (*Server, error) {
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		return nil, err
	}
	srv := &Server{
		runner: runner,
		files:  http.FileServer(http.FS(staticFS)),
		state: runState{
			phase:   "idle",
			percent: 0,
			message: "Ready",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.Handle("/static/", http.StripPrefix("/static/", srv.files))
	mux.HandleFunc("/api/start", srv.handleStart)
	mux.HandleFunc("/api/status", srv.handleStatus)
	mux.HandleFunc("/api/results", srv.handleResults)
	srv.mux = mux
	return srv, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := content.ReadFile("index.html")
	if err != nil {
		http.Error(w, "unable to load UI", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		req.Target = "1.1.1.1"
	}

	s.mu.Lock()
	if s.state.running {
		s.mu.Unlock()
		http.Error(w, "run already in progress", http.StatusConflict)
		return
	}
	s.state.running = true
	s.state.phase = "running"
	s.state.percent = 5
	s.state.message = "Starting diagnostics…"
	s.state.results = nil
	s.mu.Unlock()

	go s.execute(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	status := Status{
		Phase:   s.state.phase,
		Percent: s.state.percent,
		Message: s.state.message,
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	res := s.state.results
	phase := s.state.phase
	s.mu.Unlock()
	if res == nil || phase != "finished" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (s *Server) execute(req RunRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := s.runner(ctx, req)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.state.phase = "error"
		s.state.percent = 100
		s.state.message = err.Error()
		s.state.running = false
		s.state.results = nil
		return
	}
	resCopy := res
	s.state.phase = "finished"
	s.state.percent = 100
	s.state.message = "Diagnostics complete"
	s.state.running = false
	s.state.results = &resCopy
}

type Status struct {
	Phase   string  `json:"phase"`
	Percent float64 `json:"percent"`
	Message string  `json:"message"`
}

package webui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cneate93/vne/internal/progress"
	"github.com/cneate93/vne/internal/report"
)

//go:embed index.html static/*
var content embed.FS

type RunRequest struct {
	Scan   bool   `json:"scan"`
	Target string `json:"target"`
}

type RunFunc func(context.Context, RunRequest, progress.Reporter) (report.Results, error)

type Server struct {
	runner RunFunc
	mux    *http.ServeMux

	mu    sync.Mutex
	state runState
	files http.Handler

	subsMu sync.Mutex
	subs   map[chan streamEvent]struct{}
}

type runState struct {
	phase   string
	percent float64
	message string
	running bool
	results *report.Results
	log     []streamEvent
}

type streamEvent struct {
	event string
	data  string
}

const maxStreamLog = 500

var phasePercents = map[string]float64{
	"idle":         0,
	"starting":     5,
	"netinfo":      12,
	"l2-scan":      25,
	"gateway":      38,
	"dns":          52,
	"wan":          68,
	"traceroute":   80,
	"mtu":          88,
	"python-packs": 94,
	"snmp":         97,
	"finalizing":   99,
	"finished":     100,
	"error":        100,
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
		subs: make(map[chan streamEvent]struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.Handle("/static/", http.StripPrefix("/static/", srv.files))
	mux.HandleFunc("/api/start", srv.handleStart)
	mux.HandleFunc("/api/status", srv.handleStatus)
	mux.HandleFunc("/api/results", srv.handleResults)
	mux.HandleFunc("/api/stream", srv.handleStream)
	srv.mux = mux
	srv.recordPhase("idle", "Ready", false)
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
	s.state.phase = "starting"
	s.state.percent = 5
	s.state.message = "Starting diagnostics…"
	s.state.results = nil
	s.state.log = nil
	s.mu.Unlock()

	s.recordPhase("starting", "Starting diagnostics…", true)
	s.recordStep("Starting diagnostics…")

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
	progress := &progressEmitter{server: s}
	res, err := s.runner(ctx, req, progress)

	s.mu.Lock()
	if err != nil {
		s.state.phase = "error"
		s.state.percent = 100
		s.state.message = err.Error()
		s.state.running = false
		s.state.results = nil
		s.mu.Unlock()
		s.recordPhase("error", err.Error(), false)
		s.recordStep(fmt.Sprintf("Run failed: %s", err.Error()))
		s.recordDone("error", err.Error())
		return
	}
	resCopy := res
	s.state.phase = "finished"
	s.state.percent = 100
	s.state.message = "Diagnostics complete"
	s.state.running = false
	s.state.results = &resCopy
	s.mu.Unlock()
	s.recordPhase("finished", "Diagnostics complete", false)
	s.recordStep("Diagnostics complete.")
	s.recordDone("finished", "Diagnostics complete")
}

type Status struct {
	Phase   string  `json:"phase"`
	Percent float64 `json:"percent"`
	Message string  `json:"message"`
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan streamEvent, 32)
	s.addSubscriber(ch)
	defer s.removeSubscriber(ch)

	s.mu.Lock()
	history := append([]streamEvent(nil), s.state.log...)
	s.mu.Unlock()

	for _, evt := range history {
		fmt.Fprintf(w, "event: %s\n", evt.event)
		fmt.Fprintf(w, "data: %s\n\n", evt.data)
	}
	flusher.Flush()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\n", evt.event)
			fmt.Fprintf(w, "data: %s\n\n", evt.data)
			flusher.Flush()
		}
	}
}

func (s *Server) addSubscriber(ch chan streamEvent) {
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
}

func (s *Server) removeSubscriber(ch chan streamEvent) {
	s.subsMu.Lock()
	if _, ok := s.subs[ch]; ok {
		delete(s.subs, ch)
		close(ch)
	}
	s.subsMu.Unlock()
}

func (s *Server) recordPhase(name, message string, reset bool) {
	s.mu.Lock()
	if reset {
		s.state.log = nil
	}
	s.state.phase = name
	if pct, ok := phasePercents[name]; ok {
		s.state.percent = pct
	}
	if message != "" {
		s.state.message = message
	}
	percent := s.state.percent
	currentMessage := s.state.message
	s.mu.Unlock()

	payload := map[string]any{
		"name":    name,
		"percent": percent,
	}
	if currentMessage != "" {
		payload["message"] = currentMessage
	}
	if reset {
		payload["reset"] = true
	}
	s.broadcast("phase", payload, reset)
}

func (s *Server) recordStep(msg string) {
	if msg == "" {
		return
	}
	s.mu.Lock()
	s.state.message = msg
	s.mu.Unlock()
	s.broadcast("step", map[string]any{"msg": msg}, false)
}

func (s *Server) recordDone(status, message string) {
	payload := map[string]any{"status": status}
	if message != "" {
		payload["message"] = message
	}
	s.broadcast("done", payload, false)
}

func (s *Server) broadcast(event string, payload any, reset bool) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	evt := streamEvent{event: event, data: string(data)}
	s.mu.Lock()
	if reset {
		s.state.log = nil
	}
	s.state.log = append(s.state.log, evt)
	if len(s.state.log) > maxStreamLog {
		s.state.log = s.state.log[len(s.state.log)-maxStreamLog:]
	}
	s.mu.Unlock()

	s.subsMu.Lock()
	for ch := range s.subs {
		select {
		case ch <- evt:
		default:
		}
	}
	s.subsMu.Unlock()
}

type progressEmitter struct {
	server *Server
}

func (p *progressEmitter) Phase(name string) {
	p.server.recordPhase(name, "", false)
}

func (p *progressEmitter) Step(msg string) {
	p.server.recordStep(msg)
}

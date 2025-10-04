package webui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cneate93/vne/internal/history"
	"github.com/cneate93/vne/internal/progress"
	"github.com/cneate93/vne/internal/report"
	"github.com/cneate93/vne/internal/sshx"
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
	hist  *history.Store

	subsMu sync.Mutex
	subs   map[chan streamEvent]struct{}
}

type runState struct {
	phase        string
	percent      float64
	message      string
	running      bool
	results      *report.Results
	log          []streamEvent
	baseFindings []report.Finding
	historyID    string
}

type streamEvent struct {
	event string
	data  string
}

const maxStreamLog = 500

type vendorCreds struct {
	FortiHost   string `json:"forti_host"`
	FortiUser   string `json:"forti_user"`
	FortiPass   string `json:"forti_pass"`
	CiscoHost   string `json:"cisco_host"`
	CiscoUser   string `json:"cisco_user"`
	CiscoPass   string `json:"cisco_pass"`
	CiscoSecret string `json:"cisco_secret"`
	CiscoPort   int    `json:"cisco_port"`
}

func (c *vendorCreds) normalize() {
	if c == nil {
		return
	}
	c.FortiHost = strings.TrimSpace(c.FortiHost)
	c.FortiUser = strings.TrimSpace(c.FortiUser)
	c.FortiPass = strings.TrimSpace(c.FortiPass)
	c.CiscoHost = strings.TrimSpace(c.CiscoHost)
	c.CiscoUser = strings.TrimSpace(c.CiscoUser)
	c.CiscoPass = strings.TrimSpace(c.CiscoPass)
	c.CiscoSecret = strings.TrimSpace(c.CiscoSecret)
}

func (c vendorCreds) hasForti() bool {
	return c.FortiHost != "" && c.FortiUser != "" && c.FortiPass != ""
}

func (c vendorCreds) hasCisco() bool {
	return c.CiscoHost != "" && c.CiscoUser != "" && c.CiscoPass != ""
}

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
		hist: history.NewStore("runs", 20),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.Handle("/static/", http.StripPrefix("/static/", srv.files))
	mux.HandleFunc("/api/start", srv.handleStart)
	mux.HandleFunc("/api/status", srv.handleStatus)
	mux.HandleFunc("/api/results", srv.handleResults)
	mux.HandleFunc("/api/bundle", srv.handleBundle)
	mux.HandleFunc("/api/vendor", srv.handleVendor)
	mux.HandleFunc("/api/stream", srv.handleStream)
	mux.HandleFunc("/api/history", srv.handleHistory)
	mux.HandleFunc("/api/run/", srv.handleRun)
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
	s.state.historyID = ""
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
	historyID := s.state.historyID
	s.mu.Unlock()
	if res == nil || phase != "finished" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	response := struct {
		*report.Results
		HistoryID string `json:"history_id,omitempty"`
	}{
		Results:   res,
		HistoryID: historyID,
	}
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.hist == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
		return
	}
	entries, err := s.hist.List()
	if err != nil {
		http.Error(w, "unable to load run history", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.hist == nil {
		http.NotFound(w, r)
		return
	}
	const prefix = "/api/run/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	encodedID := strings.TrimPrefix(r.URL.Path, prefix)
	if encodedID == "" {
		http.Error(w, "run id required", http.StatusBadRequest)
		return
	}
	if strings.Contains(encodedID, "/") {
		http.NotFound(w, r)
		return
	}
	runID, err := url.PathUnescape(encodedID)
	if err != nil {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return
	}
	res, err := s.hist.Load(runID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unable to load run", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
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
	resultsCopy := *res
	raws := map[string][]byte{
		"gateway-ping.txt": []byte(resultsCopy.GwPing.Raw),
		"wan-ping.txt":     []byte(resultsCopy.WanPing.Raw),
		"traceroute.txt":   []byte(resultsCopy.Trace.Raw),
	}
	bundle, err := report.BundleBytes(resultsCopy, raws)
	if err != nil {
		http.Error(w, "unable to build bundle", http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("vne-evidence-%s.zip", resultsCopy.When.Format("20060102-1504"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Write(bundle)
}

func (s *Server) handleVendor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds vendorCreds
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	creds.normalize()

	s.mu.Lock()
	if s.state.running {
		s.mu.Unlock()
		http.Error(w, "run already in progress", http.StatusConflict)
		return
	}
	if s.state.results == nil {
		s.mu.Unlock()
		http.Error(w, "no completed run available", http.StatusBadRequest)
		return
	}
	suggestions := append([]string(nil), s.state.results.VendorSuggestions...)
	if len(suggestions) == 0 {
		s.mu.Unlock()
		http.Error(w, "no vendor packs suggested", http.StatusBadRequest)
		return
	}
	runForti := containsString(suggestions, "fortigate") && creds.hasForti()
	runCisco := containsString(suggestions, "cisco_ios") && creds.hasCisco()
	if !runForti && !runCisco {
		s.mu.Unlock()
		http.Error(w, "no vendor credentials provided", http.StatusBadRequest)
		return
	}
	s.state.running = true
	s.state.phase = "python-packs"
	if pct, ok := phasePercents["python-packs"]; ok {
		s.state.percent = pct
	}
	s.state.message = "Running vendor checks…"
	s.mu.Unlock()

	s.recordPhase("python-packs", "Running vendor checks…", false)
	s.recordStep("Running vendor checks…")

	go s.executeVendor(creds, suggestions)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "vendor-running"})
}

func (s *Server) execute(req RunRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	progress := &progressEmitter{server: s}
	res, err := s.runner(ctx, req, progress)

	if err != nil {
		s.mu.Lock()
		s.state.phase = "error"
		s.state.percent = 100
		s.state.message = err.Error()
		s.state.running = false
		s.state.results = nil
		s.state.historyID = ""
		s.mu.Unlock()
		s.recordPhase("error", err.Error(), false)
		s.recordStep(fmt.Sprintf("Run failed: %s", err.Error()))
		s.recordDone("error", err.Error())
		return
	}
	resCopy := res
	historyID := ""
	if s.hist != nil {
		if id, saveErr := s.hist.Save(resCopy); saveErr != nil {
			s.recordStep(fmt.Sprintf("⚠️ Unable to store run history: %v", saveErr))
		} else {
			historyID = id
		}
	}
	s.mu.Lock()
	s.state.phase = "finished"
	s.state.percent = 100
	s.state.message = "Diagnostics complete"
	s.state.running = false
	s.state.results = &resCopy
	s.state.baseFindings = append([]report.Finding(nil), resCopy.Findings...)
	s.state.historyID = historyID
	s.mu.Unlock()
	s.recordPhase("finished", "Diagnostics complete", false)
	s.recordStep("Diagnostics complete.")
	s.recordDone("finished", "Diagnostics complete")
}

func (s *Server) executeVendor(creds vendorCreds, suggestions []string) {
	pythonPath := defaultPythonPath()
	shouldRunForti := containsString(suggestions, "fortigate") && creds.hasForti()
	shouldRunCisco := containsString(suggestions, "cisco_ios") && creds.hasCisco()

	var fortiRaw map[string]any
	var ciscoRaw *report.CiscoPackResults
	var vendorSummaries []report.Finding
	var vendorFindings []report.Finding
	var updatedCopy report.Results
	var haveUpdated bool
	var historyID string

	if shouldRunForti {
		s.recordStep("→ Running FortiGate vendor pack…")
		payload := map[string]any{
			"host":     creds.FortiHost,
			"username": creds.FortiUser,
			"password": creds.FortiPass,
			"commands": map[string]string{
				"interfaces": "get hardware nic",
				"routes":     "get router info routing-table all",
			},
		}
		parserPath := filepath.Join("packs", "python", "fortigate", "parser.py")
		out, err := sshx.RunPythonPack(pythonPath, parserPath, payload)
		if err != nil {
			msg := fmt.Sprintf("FortiGate vendor pack error: %v", err)
			s.recordStep(msg)
			vendorSummaries = append(vendorSummaries, report.Finding{Severity: "info", Message: msg})
		} else {
			var parsed map[string]any
			if err := json.Unmarshal(out, &parsed); err != nil {
				msg := fmt.Sprintf("FortiGate vendor pack parse error: %v", err)
				s.recordStep(msg)
				vendorSummaries = append(vendorSummaries, report.Finding{Severity: "info", Message: msg})
			} else {
				fortiRaw = parsed
				vendorSummaries = append(vendorSummaries, report.Finding{Severity: "info", Message: "FortiGate vendor pack completed."})
			}
		}
	}

	if shouldRunCisco {
		s.recordStep("→ Running Cisco IOS vendor pack…")
		payload := map[string]any{
			"host":     creds.CiscoHost,
			"username": creds.CiscoUser,
			"password": creds.CiscoPass,
		}
		if creds.CiscoSecret != "" {
			payload["secret"] = creds.CiscoSecret
		}
		if creds.CiscoPort != 0 && creds.CiscoPort != 22 {
			payload["port"] = creds.CiscoPort
		}
		parserPath := filepath.Join("packs", "python", "cisco_ios", "parser.py")
		out, err := sshx.RunPythonPack(pythonPath, parserPath, payload)
		if err != nil {
			msg := fmt.Sprintf("Cisco IOS vendor pack error: %v", err)
			s.recordStep(msg)
			vendorSummaries = append(vendorSummaries, report.Finding{Severity: "info", Message: msg})
		} else {
			var parsed report.CiscoPackResults
			if err := json.Unmarshal(out, &parsed); err != nil {
				msg := fmt.Sprintf("Cisco IOS vendor pack parse error: %v", err)
				s.recordStep(msg)
				vendorSummaries = append(vendorSummaries, report.Finding{Severity: "info", Message: msg})
			} else {
				ciscoRaw = &parsed
				vendorSummaries = append(vendorSummaries, report.Finding{
					Severity: "info",
					Message:  fmt.Sprintf("Cisco IOS vendor pack completed with %d finding(s).", len(parsed.Findings)),
				})
				if len(parsed.Findings) > 0 {
					vendorFindings = append(vendorFindings, parsed.Findings...)
				}
			}
		}
	}

	s.mu.Lock()
	if s.state.results != nil {
		resCopy := *s.state.results
		if fortiRaw != nil {
			resCopy.FortiRaw = fortiRaw
		}
		if shouldRunForti && fortiRaw == nil {
			resCopy.FortiRaw = nil
		}
		if ciscoRaw != nil {
			resCopy.CiscoIOS = ciscoRaw
		}
		if shouldRunCisco && ciscoRaw == nil {
			resCopy.CiscoIOS = nil
		}
		if len(vendorSummaries) > 0 {
			resCopy.VendorSummaries = append([]report.Finding(nil), vendorSummaries...)
		} else {
			resCopy.VendorSummaries = nil
		}
		if len(vendorFindings) > 0 {
			resCopy.VendorFindings = append([]report.Finding(nil), vendorFindings...)
		} else {
			resCopy.VendorFindings = nil
		}
		baseFindings := append([]report.Finding(nil), s.state.baseFindings...)
		if len(baseFindings) > 0 || len(vendorFindings) > 0 {
			resCopy.Findings = append(baseFindings, vendorFindings...)
		} else {
			resCopy.Findings = nil
		}
		s.state.results = &resCopy
		updatedCopy = resCopy
		haveUpdated = true
	}
	s.state.running = false
	s.state.phase = "finished"
	s.state.percent = 100
	s.state.message = "Vendor checks complete"
	historyID = s.state.historyID
	s.mu.Unlock()

	if haveUpdated && historyID != "" && s.hist != nil {
		if err := s.hist.Update(historyID, updatedCopy); err != nil {
			s.recordStep(fmt.Sprintf("⚠️ Unable to update run history: %v", err))
		}
	}

	s.recordPhase("finished", "Vendor checks complete", false)
	s.recordStep("Vendor checks complete.")
	s.recordDone("finished", "Vendor checks complete")
}

func containsString(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func defaultPythonPath() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
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

package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/report"
)

const (
	defaultDir     = "runs"
	defaultMaxRuns = 20
)

type Store struct {
	dir string
	max int
}

type Entry struct {
	ID             string    `json:"id"`
	When           time.Time `json:"when"`
	Target         string    `json:"target,omitempty"`
	Classification string    `json:"classification,omitempty"`
}

func NewStore(dir string, max int) *Store {
	if strings.TrimSpace(dir) == "" {
		dir = defaultDir
	}
	if max <= 0 {
		max = defaultMaxRuns
	}
	return &Store{dir: dir, max: max}
}

func (s *Store) Save(res report.Results) (string, error) {
	if s == nil {
		return "", errors.New("nil history store")
	}
	resCopy := res
	when := resCopy.When
	if when.IsZero() {
		when = time.Now()
	}
	resCopy.When = when.UTC()

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return "", err
	}

	baseID := resCopy.When.Format("20060102-150405")
	runID := baseID
	for i := 1; ; i++ {
		path := s.pathFor(runID)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		runID = fmt.Sprintf("%s-%02d", baseID, i)
	}

	data, err := json.MarshalIndent(resCopy, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(s.pathFor(runID), data, 0o644); err != nil {
		return "", err
	}
	if err := s.prune(); err != nil {
		return runID, err
	}
	return runID, nil
}

func (s *Store) Update(id string, res report.Results) error {
	if s == nil {
		return errors.New("nil history store")
	}
	cleanID, err := sanitizeID(id)
	if err != nil {
		return err
	}
	resCopy := res
	if resCopy.When.IsZero() {
		resCopy.When = time.Now().UTC()
	} else {
		resCopy.When = resCopy.When.UTC()
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(resCopy, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.pathFor(cleanID), data, 0o644)
}

func (s *Store) List() ([]Entry, error) {
	if s == nil {
		return nil, errors.New("nil history store")
	}
	names, err := s.sortedRunFiles()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	entries := make([]Entry, 0, len(names))
	for idx, name := range names {
		if s.max > 0 && idx >= s.max {
			break
		}
		id := strings.TrimSuffix(name, ".json")
		res, err := s.readMeta(id)
		if err != nil {
			continue
		}
		entries = append(entries, res)
	}
	return entries, nil
}

func (s *Store) Load(id string) (*report.Results, error) {
	if s == nil {
		return nil, errors.New("nil history store")
	}
	cleanID, err := sanitizeID(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.pathFor(cleanID))
	if err != nil {
		return nil, err
	}
	var res report.Results
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *Store) prune() error {
	names, err := s.sortedRunFiles()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if s.max <= 0 || len(names) <= s.max {
		return nil
	}
	for _, name := range names[s.max:] {
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

func (s *Store) sortedRunFiles() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".json") {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return names[i] > names[j]
	})
	return names, nil
}

func (s *Store) readMeta(id string) (Entry, error) {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return Entry{}, err
	}
	data, err := os.ReadFile(s.pathFor(cleanID))
	if err != nil {
		return Entry{}, err
	}
	var meta struct {
		When           time.Time `json:"when"`
		Target         string    `json:"target_host"`
		Classification string    `json:"classification"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return Entry{}, err
	}
	return Entry{
		ID:             cleanID,
		When:           meta.When,
		Target:         strings.TrimSpace(meta.Target),
		Classification: strings.TrimSpace(meta.Classification),
	}, nil
}

func (s *Store) pathFor(id string) string {
	return filepath.Join(s.dir, fmt.Sprintf("%s.json", id))
}

func sanitizeID(id string) (string, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return "", os.ErrNotExist
	}
	if strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, "/\\") {
		return "", os.ErrNotExist
	}
	return trimmed, nil
}

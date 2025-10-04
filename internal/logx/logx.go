package logx

import (
	"io"
	"log"
	"os"
	"sync"
)

var (
	mu     sync.Mutex
	logger = log.New(io.Discard, "", log.LstdFlags)
	closer io.Closer
)

// Init configures the logger. When verbose is true the logger writes to vne.log.
func Init(verbose bool) error {
	mu.Lock()
	defer mu.Unlock()

	if closer != nil {
		_ = closer.Close()
		closer = nil
	}

	if verbose {
		f, err := os.OpenFile("vne.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		logger.SetOutput(f)
		closer = f
	} else {
		logger.SetOutput(io.Discard)
	}

	return nil
}

// Printf writes a formatted log entry when verbose logging is enabled.
func Printf(format string, v ...any) {
	mu.Lock()
	defer mu.Unlock()
	logger.Printf(format, v...)
}

// Println writes a log entry when verbose logging is enabled.
func Println(v ...any) {
	mu.Lock()
	defer mu.Unlock()
	logger.Println(v...)
}

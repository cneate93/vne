package logx

import (
	"io"
	"log"
	"os"
)

var logFile *os.File

// Configure sets up logging based on the verbose flag. When verbose is false,
// logs are discarded. When verbose is true, logs are written to vne.log with
// timestamps.
func Configure(verbose bool) error {
	if !verbose {
		log.SetOutput(io.Discard)
		log.SetFlags(0)
		return nil
	}

	f, err := os.OpenFile("vne.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	logFile = f
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
	return nil
}

// Close releases any resources associated with logging.
func Close() error {
	if logFile == nil {
		return nil
	}
	err := logFile.Close()
	logFile = nil
	return err
}

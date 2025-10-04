package sshx

import (
	"bytes"
	"encoding/json"
	"os/exec"
)

// RunPythonPack executes a Python script with a JSON payload piped to stdin.
// It returns the stdout of the Python script (usually JSON output).
func RunPythonPack(pythonPath, scriptPath string, payload any) ([]byte, error) {
	in, _ := json.Marshal(payload)

	cmd := exec.Command(pythonPath, scriptPath)
	cmd.Stdin = bytes.NewReader(in)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.Bytes(), err
}

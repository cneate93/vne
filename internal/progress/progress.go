package progress

// Reporter receives structured updates about a running diagnostics session.
type Reporter interface {
	// Phase marks the transition to a new high-level phase of the run.
	Phase(name string)
	// Step records a human-readable message for the live console output.
	Step(msg string)
}

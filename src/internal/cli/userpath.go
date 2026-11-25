package cli

// userPathStore reads and writes the user's own PATH where the OS keeps it.
type userPathStore interface {
	Get() (string, error)
	Set(string) error
}

// userPath is the user PATH store: the registry on Windows, nil elsewhere.
var userPath = osUserPath()

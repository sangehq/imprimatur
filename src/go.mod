module github.com/sangehq/imprimatur/src

go 1.27.4

require (
	github.com/simtabi/go-notifykit/src v0.0.0-20261108151612-b1d96c3bd177
	golang.org/x/sys v0.50.0
)

// v1.8.0-rc.1 was published before the history was reset to v0.1.0;
// its commit no longer exists in the repository.
retract v1.8.0-rc.1

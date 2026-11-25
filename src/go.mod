module github.com/sangehq/imprimatur/src

go 1.27.4

require (
	github.com/anchore/go-macholibre v0.1.1
	github.com/anchore/quill v0.7.1
	github.com/github/smimesign v0.2.0
	github.com/simtabi/go-notifykit/src v0.1.1
	golang.org/x/sys v0.50.0
	software.sslmate.com/src/go-pkcs12 v0.7.0
)

require (
	github.com/anchore/go-logger v0.0.0-20251106021608-a5b0513fa9a9 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

// v1.8.0-rc.1 was published before the history was reset to v0.1.0;
// its commit no longer exists in the repository.
retract v1.8.0-rc.1

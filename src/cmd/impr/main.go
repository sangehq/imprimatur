// Command impr signs and verifies release artifacts with signing profiles.
package main

import (
	"os"

	"github.com/sangehq/imprimatur/src/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }

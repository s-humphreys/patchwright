// Command patchwright turns noisy container-vulnerability scanner output into a
// deduplicated, owner-attributed, actionable list.
package main

import (
	"os"

	"github.com/s-humphreys/patchwright/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

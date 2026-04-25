package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"mokos_lockdoor/internal/hashutil"
)

func main() {
	password := flag.String("password", "", "plain password to hash")
	flag.Parse()

	input := *password
	if input == "" {
		if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed reading stdin: %v\n", err)
				os.Exit(1)
			}
			// Match common shell usage: trim line ending from piped input.
			input = string(bytes.TrimRight(data, "\r\n"))
		}
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/md5gen -password 'your-password' OR echo -n 'your-password' | go run ./cmd/md5gen")
		os.Exit(1)
	}

	fmt.Println(hashutil.MD5Hex(input))
}

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	recursive := flag.Bool("r", false, "Recursively search directories")
	ignoreCase := flag.Bool("i", false, "Ignore case")
	workers := flag.Int("workers", 10, "Concurrency limit")
	depth := flag.Int("depth", 2, "Decoder combination depth")
	verbose := flag.Bool("v", false, "Verbose output")

	var afterContext, beforeContext int
	flag.IntVar(&afterContext, "A", 0, "Print NUM characters of trailing context")
	flag.IntVar(&beforeContext, "B", 0, "Print NUM characters of leading context")
	var context int
	flag.IntVar(&context, "C", 0, "Print NUM characters of output context")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: flagrep [options] PATTERN [FILE...] OR flagrep [options] PATTERN < stdin")
		flag.Usage()
		os.Exit(1)
	}

	pattern := args[0]
	paths := args[1:]

	// if C is set, A and B are set to C, just like in grep
	if context > 0 {
		if afterContext == 0 {
			afterContext = context
		}
		if beforeContext == 0 {
			beforeContext = context
		}
	}
	// default is 10 chars before and 30 chars after
	if afterContext == 0 && beforeContext == 0 && context == 0 {
		beforeContext = 10
		afterContext = 30
	}

	caseSensitive := !*ignoreCase

	searcher := NewSearcher(paths, pattern, *recursive, caseSensitive, *workers, *depth, beforeContext, afterContext, *verbose)

	if *verbose {
		fmt.Printf("Starting search for pattern %q (Recursive: %v, Depth: %d)\n", pattern, *recursive, *depth)
	}

	// just in case
	fmt.Println("*Expect false positives")

	err := searcher.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

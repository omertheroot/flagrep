package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
)

var version = "1.1.0"

func main() {
	config, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not load config: %v\n", err)
	}

	recursive := flag.Bool("r", config.Recursive, "Recursively search directories")
	ignoreCase := flag.Bool("i", config.IgnoreCase, "Ignore case")
	workers := flag.Int("workers", config.Workers, "Concurrency limit")
	depth := flag.Int("depth", config.Depth, "Decoder combination depth")
	verbose := flag.Bool("v", config.Verbose, "Verbose output")

	var afterContext, beforeContext int
	flag.IntVar(&afterContext, "A", config.AfterContext, "Print NUM characters of trailing context")
	flag.IntVar(&beforeContext, "B", config.BeforeContext, "Print NUM characters of leading context")
	var context int
	flag.IntVar(&context, "C", config.Context, "Print NUM characters of output context")

	useRegex := flag.Bool("e", config.UseRegex, "Enable regex mode")
	jsonOutput := flag.Bool("json", config.JSONOutput, "Enable JSON output")

	defaultExclude := strings.Join(config.ExcludeDirs, ",")
	excludeDirStr := flag.String("exclude-dir", defaultExclude, "Comma-separated list of directories to exclude")

	entropyThreshold := flag.Float64("entropy-threshold", config.EntropyThreshold, "Only process content with entropy >= threshold (0 to disable)")

	defaultMagic := strings.Join(config.MagicFilter, ",")
	magicFilter := flag.String("magic", defaultMagic, "Comma-separated list of magic types to include (e.g., ELF,MZ,PDF)")

	tuiMode := flag.Bool("tui", config.TUIMode, "Enable interactive TUI mode")
	showVersion := flag.Bool("version", false, "Show version information")

	cpuProfile := flag.String("cpuprofile", "", "Write CPU profile to file")
	memProfile := flag.String("memprofile", "", "Write memory profile to file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: flagrep [options] PATTERN [FILE...] OR flagrep [options] PATTERN < stdin\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfig: loaded from ~/.flagrep.json (if present)\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("flagrep version %s\n", version)
		os.Exit(0)
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create CPU profile: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "Could not start CPU profile: %v\n", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	if *memProfile != "" {
		defer func() {
			f, err := os.Create(*memProfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not create memory profile: %v\n", err)
				return
			}
			defer f.Close()
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "Could not write memory profile: %v\n", err)
			}
		}()
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	pattern := args[0]
	paths := args[1:]

	if context > 0 {
		if afterContext == 0 {
			afterContext = context
		}
		if beforeContext == 0 {
			beforeContext = context
		}
	}
	if afterContext == 0 && beforeContext == 0 && context == 0 && config.AfterContext == 0 && config.BeforeContext == 0 {
		beforeContext = 10
		afterContext = 30
	}

	caseSensitive := !*ignoreCase

	var excludedDirs []string
	if *excludeDirStr != "" {
		excludedDirs = strings.Split(*excludeDirStr, ",")
		for i := range excludedDirs {
			excludedDirs[i] = strings.TrimSpace(excludedDirs[i])
		}
	}

	var magicTypes []string
	if *magicFilter != "" {
		magicTypes = strings.Split(*magicFilter, ",")
		for i := range magicTypes {
			magicTypes[i] = strings.TrimSpace(strings.ToUpper(magicTypes[i]))
		}
	}

	searcher := NewSearcher(paths, pattern, *recursive, caseSensitive, *useRegex, *workers, *depth, beforeContext, afterContext, *verbose, *jsonOutput, excludedDirs, *entropyThreshold, magicTypes, *tuiMode)

	if *verbose {
		fmt.Printf("Starting search for pattern %q (Recursive: %v, Depth: %d)\n", pattern, *recursive, *depth)
	}

	if !*tuiMode {
		fmt.Println("*Expect false positives")
	}

	err = searcher.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if *tuiMode && searcher.MatchCollector != nil {
		tui := NewTUI(searcher.MatchCollector.Matches)
		tui.Run()
	}
}

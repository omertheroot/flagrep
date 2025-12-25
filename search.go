package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Searcher struct {
	Paths            []string
	Pattern          string
	Recursive        bool
	CaseSensitive    bool
	Concurrency      int
	Depth            int
	Verbose          bool
	Decoders         map[string]DecoderFunc
	Regexp           *regexp.Regexp
	ContextBefore    int
	ContextAfter     int
	ExcludedDirs     []string
	JsonOutput       bool
	EntropyThreshold float64
	MagicTypes       []string
	TUIMode          bool
	MatchCollector   *MatchCollector
}

func NewSearcher(paths []string, pattern string, recursive, caseSensitive, isRegex bool, concurrency, depth, contextBefore, contextAfter int, verbose, jsonOutput bool, excludedDirs []string, entropyThreshold float64, magicTypes []string, tuiMode bool) *Searcher {
	var regexPattern string
	if isRegex {
		regexPattern = pattern
	} else {
		regexPattern = regexp.QuoteMeta(pattern)
	}

	if !caseSensitive {
		regexPattern = "(?i)" + regexPattern
	}

	re := regexp.MustCompile(regexPattern)

	var collector *MatchCollector
	if tuiMode {
		collector = NewMatchCollector()
	}

	return &Searcher{
		Paths:            paths,
		Pattern:          pattern,
		Recursive:        recursive,
		CaseSensitive:    caseSensitive,
		Concurrency:      concurrency,
		Depth:            depth,
		ContextBefore:    contextBefore,
		ContextAfter:     contextAfter,
		Verbose:          verbose,
		Decoders:         getDecoders(),
		Regexp:           re,
		ExcludedDirs:     excludedDirs,
		JsonOutput:       jsonOutput,
		EntropyThreshold: entropyThreshold,
		MagicTypes:       magicTypes,
		TUIMode:          tuiMode,
		MatchCollector:   collector,
	}
}

func (s *Searcher) Run() error {
	fileChan := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				s.processFile(path)
			}
		}()
	}

	// if no paths provided, read from stdin
	if len(s.Paths) == 0 {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		s.searchBFS(string(content), "(stdin)")
		return nil
	}

	// walk the directories and send files to the chan
	for _, path := range s.Paths {
		if path == "-" {
			content, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Printf("Error reading stdin: %v\n", err)
				continue
			}
			s.searchBFS(string(content), "(stdin)")
			continue
		}

		err := s.walk(path, fileChan)
		if err != nil {
			fmt.Printf("Error walking path %s: %v\n", path, err)
		}
	}

	close(fileChan)
	wg.Wait()

	return nil
}

func (s *Searcher) walk(root string, fileChan chan<- string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		fileChan <- root
		return nil
	}

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if s.Verbose {
				fmt.Printf("Error accessing path %q: %v\n", path, err)
			}
			return nil
		}

		if info.IsDir() {
			base := filepath.Base(path)
			for _, excluded := range s.ExcludedDirs {
				if base == excluded {
					if s.Verbose {
						fmt.Printf("Skipping excluded directory: %s\n", path)
					}
					return filepath.SkipDir
				}
			}
			if !s.Recursive && path != root {
				return filepath.SkipDir
			}
		} else {
			fileChan <- path
		}
		return nil
	})
}

func (s *Searcher) processFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		if s.Verbose {
			fmt.Printf("Error reading file %s: %v\n", path, err)
		}
		return
	}

	// Skip files not matching magic filter if enabled
	if len(s.MagicTypes) > 0 {
		if !MatchesMagicFilter(content, s.MagicTypes) {
			detected := DetectMagic(content)
			if s.Verbose {
				fmt.Printf("Skipping %s (magic: %s, filter: %v)\n", path, detected, s.MagicTypes)
			}
			return
		}
		if s.Verbose {
			fmt.Printf("Processing %s (magic: %s)\n", path, DetectMagic(content))
		}
	}

	// Skip files below entropy threshold if enabled
	if s.EntropyThreshold > 0 {
		entropy := CalculateEntropy(content)
		if entropy < s.EntropyThreshold {
			if s.Verbose {
				fmt.Printf("Skipping %s (entropy %.2f < threshold %.2f)\n", path, entropy, s.EntropyThreshold)
			}
			return
		}
		if s.Verbose {
			fmt.Printf("Processing %s (entropy %.2f >= threshold %.2f)\n", path, entropy, s.EntropyThreshold)
		}
	}

	s.searchBFS(string(content), path)
}

type searchState struct {
	content         string
	appliedDecoders []string
	depth           int
}

func (s *Searcher) searchBFS(initialContent, path string) {
	queue := []searchState{
		{
			content:         initialContent,
			appliedDecoders: []string{},
			depth:           0,
		},
	}

	for len(queue) > 0 {
		currentState := queue[0]
		queue = queue[1:]
		if s.matches(currentState.content) {
			//found match
			s.printMatch(path, currentState.appliedDecoders, currentState.content)
		}

		// stop if we reached max depth
		if currentState.depth >= s.Depth {
			continue
		}

		// generate next states
		for name, decoder := range s.Decoders {
			decoded, err := decoder(currentState.content)
			if err == nil && decoded != "" && decoded != currentState.content {
				newApplied := make([]string, len(currentState.appliedDecoders))
				copy(newApplied, currentState.appliedDecoders)
				newApplied = append(newApplied, name)

				queue = append(queue, searchState{
					content:         decoded,
					appliedDecoders: newApplied,
					depth:           currentState.depth + 1,
				})
			}
		}
	}
}

func (s *Searcher) matches(content string) bool {
	return s.Regexp.MatchString(content)
}

func (s *Searcher) printMatch(path string, decoders []string, content string) {
	decoderStr := "None"
	if len(decoders) > 0 {
		decoderStr = strings.Join(decoders, " -> ")
	}

	const maxMatchesPerFile = 5
	matches := s.Regexp.FindAllStringIndex(content, maxMatchesPerFile+1)

	for i, loc := range matches {
		if i >= maxMatchesPerFile {
			if !s.JsonOutput && !s.TUIMode {
				fmt.Printf("[MATCH] File: %s | Decoders: %s | ... and more matches ...\n", path, decoderStr)
			}
			break
		}

		matchIndex := loc[0]
		matchLen := loc[1] - loc[0]

		start := max(matchIndex-s.ContextBefore, 0)
		end := min(matchIndex+matchLen+s.ContextAfter, len(content))

		// extract from original content
		prefix := content[start:matchIndex]
		match := content[matchIndex : matchIndex+matchLen]
		suffix := content[matchIndex+matchLen : end]
		context := prefix + match + suffix

		// TUI mode: collect matches instead of printing
		if s.TUIMode && s.MatchCollector != nil {
			s.MatchCollector.Add(path, decoders, match, context, matchIndex)
			continue
		}

		if s.JsonOutput {
			// Create a struct for JSON output
			output := struct {
				File     string   `json:"file"`
				Decoders []string `json:"decoders"`
				Match    string   `json:"match"`
				Context  string   `json:"context"`
				Offset   int      `json:"offset"`
			}{
				File:     path,
				Decoders: decoders,
				Match:    match,
				Context:  context,
				Offset:   matchIndex,
			}
			jsonBytes, err := json.Marshal(output)
			if err == nil {
				fmt.Println(string(jsonBytes))
			}
		} else {
			// escape bad chars
			prefix = strings.ReplaceAll(prefix, "\n", "\\n")
			prefix = strings.ReplaceAll(prefix, "\r", "\\r")
			match = strings.ReplaceAll(match, "\n", "\\n")
			match = strings.ReplaceAll(match, "\r", "\\r")
			suffix = strings.ReplaceAll(suffix, "\n", "\\n")
			suffix = strings.ReplaceAll(suffix, "\r", "\\r")

			formattedContent := fmt.Sprintf("%s\033[31m%s\033[0m%s", prefix, match, suffix)

			fmt.Printf("[MATCH] File: %s | Decoders: %s | Content: ...%s...\n", path, decoderStr, formattedContent)
		}
	}
}

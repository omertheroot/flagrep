package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Searcher struct {
	Paths         []string
	Pattern       string
	Recursive     bool
	CaseSensitive bool
	Concurrency   int
	Depth         int
	Verbose       bool
	Decoders      map[string]DecoderFunc
	Regexp        *regexp.Regexp
	ContextBefore int
	ContextAfter  int
}

func NewSearcher(paths []string, pattern string, recursive, caseSensitive bool, concurrency, depth, contextBefore, contextAfter int, verbose bool) *Searcher {
	var re *regexp.Regexp
	if caseSensitive {
		re = regexp.MustCompile(regexp.QuoteMeta(pattern))
	} else {
		re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(pattern))
	}

	return &Searcher{
		Paths:         paths,
		Pattern:       pattern,
		Recursive:     recursive,
		CaseSensitive: caseSensitive,
		Concurrency:   concurrency,
		Depth:         depth,
		ContextBefore: contextBefore,
		ContextAfter:  contextAfter,
		Verbose:       verbose,
		Decoders:      getDecoders(),
		Regexp:        re,
	}
}

func (s *Searcher) Run() error {
	fileChan := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < s.Concurrency; i++ {
		wg.Go(func() {
			for path := range fileChan {
				s.processFile(path)
			}
		})
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
		if !info.IsDir() {
			fileChan <- path
		} else if !s.Recursive && path != root {
			return filepath.SkipDir
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
			fmt.Printf("[MATCH] File: %s | Decoders: %s | ... and more matches ...\n", path, decoderStr)
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

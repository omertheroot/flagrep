package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// StringsResult contains extracted strings from a file
type StringsResult struct {
	File    string
	Strings []ExtractedString
}

// ExtractedString represents a single extracted string with metadata
type ExtractedString struct {
	Value  string
	Offset int
	Length int
}

// ExtractStrings extracts printable ASCII strings from binary data
// minLen is the minimum string length to extract (default: 4)
func ExtractStrings(data []byte, minLen int) []ExtractedString {
	if minLen < 1 {
		minLen = 4
	}

	var results []ExtractedString
	var current strings.Builder
	startOffset := 0

	for i, b := range data {
		// Printable ASCII range (32-126) plus common whitespace
		if (b >= 32 && b <= 126) || b == '\t' {
			if current.Len() == 0 {
				startOffset = i
			}
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				results = append(results, ExtractedString{
					Value:  current.String(),
					Offset: startOffset,
					Length: current.Len(),
				})
			}
			current.Reset()
		}
	}

	// Don't forget trailing string
	if current.Len() >= minLen {
		results = append(results, ExtractedString{
			Value:  current.String(),
			Offset: startOffset,
			Length: current.Len(),
		})
	}

	return results
}

// ExtractUnicodeStrings extracts UTF-16 LE strings (common in Windows binaries)
func ExtractUnicodeStrings(data []byte, minLen int) []ExtractedString {
	if minLen < 1 {
		minLen = 4
	}

	var results []ExtractedString
	var current strings.Builder
	startOffset := 0

	for i := 0; i < len(data)-1; i += 2 {
		// UTF-16 LE: low byte first, high byte should be 0 for ASCII
		if data[i+1] == 0 && data[i] >= 32 && data[i] <= 126 {
			if current.Len() == 0 {
				startOffset = i
			}
			current.WriteByte(data[i])
		} else {
			if current.Len() >= minLen {
				results = append(results, ExtractedString{
					Value:  current.String(),
					Offset: startOffset,
					Length: current.Len(),
				})
			}
			current.Reset()
		}
	}

	if current.Len() >= minLen {
		results = append(results, ExtractedString{
			Value:  current.String(),
			Offset: startOffset,
			Length: current.Len(),
		})
	}

	return results
}

// FileHashes contains hash values for a file
type FileHashes struct {
	MD5    string
	SHA256 string
}

// CalculateHashes computes MD5 and SHA256 hashes for a file
func CalculateHashes(path string) (*FileHashes, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()
	writer := io.MultiWriter(md5Hash, sha256Hash)

	if _, err := io.Copy(writer, file); err != nil {
		return nil, err
	}

	return &FileHashes{
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

// CalculateHashesFromBytes computes hashes from byte slice
func CalculateHashesFromBytes(data []byte) *FileHashes {
	md5Sum := md5.Sum(data)
	sha256Sum := sha256.Sum256(data)
	return &FileHashes{
		MD5:    hex.EncodeToString(md5Sum[:]),
		SHA256: hex.EncodeToString(sha256Sum[:]),
	}
}

// EntropyChunk represents entropy for a portion of data
type EntropyChunk struct {
	Offset  int
	Size    int
	Entropy float64
}

// CalculateEntropyHeatmap calculates entropy for chunks of data
func CalculateEntropyHeatmap(data []byte, chunkSize int) []EntropyChunk {
	if chunkSize < 1 {
		chunkSize = 256
	}

	var chunks []EntropyChunk
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]
		entropy := CalculateEntropy(chunk)

		chunks = append(chunks, EntropyChunk{
			Offset:  offset,
			Size:    len(chunk),
			Entropy: entropy,
		})
	}

	return chunks
}

// FindHighEntropyRegions finds contiguous regions with entropy above threshold
func FindHighEntropyRegions(data []byte, threshold float64, chunkSize int) []EntropyChunk {
	heatmap := CalculateEntropyHeatmap(data, chunkSize)
	var regions []EntropyChunk

	for _, chunk := range heatmap {
		if chunk.Entropy >= threshold {
			regions = append(regions, chunk)
		}
	}

	return regions
}

// RenderEntropyHeatmap creates an ASCII visualization of entropy
func RenderEntropyHeatmap(data []byte, width int) string {
	if width < 10 {
		width = 80
	}

	chunkSize := len(data) / width
	if chunkSize < 1 {
		chunkSize = 1
	}

	heatmap := CalculateEntropyHeatmap(data, chunkSize)
	var result strings.Builder

	result.WriteString("Entropy Heatmap (█=high, ░=low):\n")
	result.WriteString("0")
	result.WriteString(strings.Repeat(" ", width-6))
	result.WriteString(fmt.Sprintf("%d\n", len(data)))

	for _, chunk := range heatmap {
		// Map entropy 0-8 to characters
		level := int(chunk.Entropy * 8 / 8)
		chars := []rune{'░', '▒', '▓', '█'}
		idx := level / 2
		if idx > 3 {
			idx = 3
		}
		result.WriteRune(chars[idx])
	}
	result.WriteString("\n")

	return result.String()
}

// YaraRule represents a simple pattern matching rule
type YaraRule struct {
	Name        string
	Description string
	Strings     []YaraString
	Condition   string // "any", "all", or number
}

// YaraString is a pattern to match
type YaraString struct {
	ID       string
	Pattern  string
	IsRegex  bool
	IsHex    bool
	NoCase   bool
	compiled *regexp.Regexp
}

// YaraMatch represents a rule match
type YaraMatch struct {
	Rule    string
	File    string
	Matches map[string][]int // String ID -> offsets
}

// CompileYaraRule compiles pattern strings
func CompileYaraRule(rule *YaraRule) error {
	for i := range rule.Strings {
		s := &rule.Strings[i]
		if s.IsRegex {
			pattern := s.Pattern
			if s.NoCase {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex %s: %v", s.ID, err)
			}
			s.compiled = re
		}
	}
	return nil
}

// MatchYaraRule checks if data matches a rule
func MatchYaraRule(data []byte, rule *YaraRule) *YaraMatch {
	content := string(data)
	matches := make(map[string][]int)

	for _, s := range rule.Strings {
		var offsets []int

		if s.IsRegex && s.compiled != nil {
			locs := s.compiled.FindAllStringIndex(content, -1)
			for _, loc := range locs {
				offsets = append(offsets, loc[0])
			}
		} else if s.IsHex {
			// Convert hex pattern to bytes and search
			hexBytes, err := hex.DecodeString(strings.ReplaceAll(s.Pattern, " ", ""))
			if err == nil {
				pattern := string(hexBytes)
				idx := 0
				for {
					pos := strings.Index(content[idx:], pattern)
					if pos == -1 {
						break
					}
					offsets = append(offsets, idx+pos)
					idx += pos + len(pattern)
				}
			}
		} else {
			// Plain text search
			searchContent := content
			searchPattern := s.Pattern
			if s.NoCase {
				searchContent = strings.ToLower(content)
				searchPattern = strings.ToLower(s.Pattern)
			}
			idx := 0
			for {
				pos := strings.Index(searchContent[idx:], searchPattern)
				if pos == -1 {
					break
				}
				offsets = append(offsets, idx+pos)
				idx += pos + len(searchPattern)
			}
		}

		if len(offsets) > 0 {
			matches[s.ID] = offsets
		}
	}

	// Check condition
	matched := false
	switch rule.Condition {
	case "any":
		matched = len(matches) > 0
	case "all":
		matched = len(matches) == len(rule.Strings)
	default:
		// Assume it's a number
		var n int
		fmt.Sscanf(rule.Condition, "%d", &n)
		matched = len(matches) >= n
	}

	if !matched {
		return nil
	}

	return &YaraMatch{
		Rule:    rule.Name,
		Matches: matches,
	}
}

package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// returns decoded str
type DecoderFunc func(string) (string, error)

func getDecoders() map[string]DecoderFunc {
	return map[string]DecoderFunc{
		"reverse":            reverseDecoder,
		"space_removal":      spaceRemovalDecoder,
		"base64":             base64Decoder,
		"base64_url":         base64URLDecoder,
		"base32":             base32Decoder,
		"hex_with_spaces":    hexWithSpacesDecoder,
		"hex_without_spaces": hexWithoutSpacesDecoder,
		"hex_with_prefix":    hexWithPrefixDecoder,
		"rot13":              rot13Decoder,
		"rot47":              rot47Decoder,
		"binary":             binaryDecoder,
		"octal":              octalDecoder,
		"url":                urlDecoder,
		"html":               htmlEntityDecoder,
		"xor_bruteforce":     xorBruteForceDecoder,
		"atbash":             atbashDecoder,
		"morse":              morseDecoder,
		"unicode_escape":     unicodeEscapeDecoder,
		"base85":             base85Decoder,
		"caesar":             caesarBruteForceDecoder,
	}
}

// "olleH" -> "Hello"
func reverseDecoder(input string) (string, error) {
	runes := []rune(input)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes), nil
}

// "He llo" -> "Hello"
func spaceRemovalDecoder(input string) (string, error) {
	return strings.ReplaceAll(input, " ", ""), nil
}

// "SGVsbG8=" -> "Hello"
func base64Decoder(input string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func base64URLDecoder(input string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// "JBSWY3DP" -> "Hello"
func base32Decoder(input string) (string, error) {
	data, err := base32.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// "48 65 6c 6c 6f" -> "Hello"
func hexWithSpacesDecoder(input string) (string, error) {
	re := regexp.MustCompile(`\b([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+)\b`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		clean := strings.ReplaceAll(match, " ", "")
		data, err := hex.DecodeString(clean)
		if err != nil {
			return match
		}
		return string(data)
	}), nil
}

// "48656c6c6f" -> "Hello"
func hexWithoutSpacesDecoder(input string) (string, error) {
	re := regexp.MustCompile(`\b([0-9a-fA-F]{6,})\b`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		data, err := hex.DecodeString(match)
		if err != nil {
			return match
		}
		// we keep it if decoded content contains mostly printable chars.
		printable := 0
		for _, b := range data {
			if b >= 32 && b <= 126 {
				printable++
			}
		}
		if float64(printable)/float64(len(data)) > 0.8 {
			return string(data)
		}
		return match
	}), nil
}

// "0x48 0x65 0x6c 0x6c 0x6f" -> "Hello"
func hexWithPrefixDecoder(input string) (string, error) {
	re := regexp.MustCompile(`\b((?:0x[0-9a-fA-F]{2}(?:\s+|$))+)\b`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		clean := strings.ReplaceAll(match, "0x", "")
		clean = strings.ReplaceAll(clean, " ", "")
		data, err := hex.DecodeString(clean)
		if err != nil {
			return match
		}
		return string(data)
	}), nil
}

// "Uryyb" -> "Hello"
func rot13Decoder(input string) (string, error) {
	var result strings.Builder
	for _, r := range input {
		if r >= 'a' && r <= 'z' {
			if r >= 'a'+13 {
				result.WriteRune(r - 13)
			} else {
				result.WriteRune(r + 13)
			}
		} else if r >= 'A' && r <= 'Z' {
			if r >= 'A'+13 {
				result.WriteRune(r - 13)
			} else {
				result.WriteRune(r + 13)
			}
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// "w6==@" -> "Hello"
func rot47Decoder(input string) (string, error) {
	var result strings.Builder
	for _, r := range input {
		if r >= '!' && r <= '~' {
			result.WriteRune(33 + ((r + 14) % 94))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// "01000001" -> "A"
func binaryDecoder(input string) (string, error) {
	clean := strings.ReplaceAll(input, " ", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	if len(clean)%8 != 0 {
		return "", fmt.Errorf("invalid binary length: %d", len(clean))
	}
	var sb strings.Builder
	for i := 0; i < len(clean); i += 8 {
		val, err := strconv.ParseInt(clean[i:i+8], 2, 64)
		if err != nil {
			return "", err
		}
		sb.WriteByte(byte(val))
	}
	return sb.String(), nil
}

// "101" -> "A"
func octalDecoder(input string) (string, error) {
	parts := strings.Fields(input)
	var sb strings.Builder
	for _, part := range parts {
		if len(part) > 3 {
			return "", fmt.Errorf("invalid octal chunk")
		}
		val, err := strconv.ParseInt(part, 8, 64)
		if err != nil {
			return "", err
		}
		sb.WriteByte(byte(val))
	}
	return sb.String(), nil
}

// "%20" -> " "
func urlDecoder(input string) (string, error) {
	return url.QueryUnescape(input)
}

// "&lt;" -> "<"
func htmlEntityDecoder(input string) (string, error) {
	return html.UnescapeString(input), nil
}

// XOR brute-force decoder: tries all single-byte XOR keys (0x01-0xFF)
// Returns decoded string if ≥80% of characters are printable ASCII
func xorBruteForceDecoder(input string) (string, error) {
	data := []byte(input)
	if len(data) == 0 {
		return "", fmt.Errorf("empty input")
	}

	for key := byte(1); key != 0; key++ { // 1-255
		decoded := make([]byte, len(data))
		printable := 0

		for i, b := range data {
			decoded[i] = b ^ key
			// Check if printable ASCII (32-126) or common whitespace
			if (decoded[i] >= 32 && decoded[i] <= 126) || decoded[i] == '\n' || decoded[i] == '\r' || decoded[i] == '\t' {
				printable++
			}
		}

		// Return if ≥80% printable
		if float64(printable)/float64(len(decoded)) >= 0.8 {
			return string(decoded), nil
		}
	}

	return "", fmt.Errorf("no valid XOR key found")
}

// Atbash cipher: A↔Z, B↔Y, etc.
func atbashDecoder(input string) (string, error) {
	var result strings.Builder
	for _, r := range input {
		if r >= 'a' && r <= 'z' {
			result.WriteRune('z' - (r - 'a'))
		} else if r >= 'A' && r <= 'Z' {
			result.WriteRune('Z' - (r - 'A'))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// Morse code decoder
var morseToChar = map[string]rune{
	".-": 'A', "-...": 'B', "-.-.": 'C', "-..": 'D', ".": 'E',
	"..-.": 'F', "--.": 'G', "....": 'H', "..": 'I', ".---": 'J',
	"-.-": 'K', ".-..": 'L', "--": 'M', "-.": 'N', "---": 'O',
	".--.": 'P', "--.-": 'Q', ".-.": 'R', "...": 'S', "-": 'T',
	"..-": 'U', "...-": 'V', ".--": 'W', "-..-": 'X', "-.--": 'Y',
	"--..": 'Z', "-----": '0', ".----": '1', "..---": '2', "...--": '3',
	"....-": '4', ".....": '5', "-....": '6', "--...": '7', "---..": '8',
	"----.": '9', ".-.-.-": '.', "--..--": ',', "..--..": '?',
}

func morseDecoder(input string) (string, error) {
	// Split by word separator (multiple spaces or /)
	words := regexp.MustCompile(`\s{3,}|/`).Split(input, -1)
	var result strings.Builder

	for i, word := range words {
		if i > 0 {
			result.WriteRune(' ')
		}
		// Split letters by single space
		letters := strings.Fields(word)
		for _, letter := range letters {
			if ch, ok := morseToChar[letter]; ok {
				result.WriteRune(ch)
			}
		}
	}

	decoded := result.String()
	if decoded == "" {
		return "", fmt.Errorf("no morse code found")
	}
	return decoded, nil
}

func unicodeEscapeDecoder(input string) (string, error) {
	re := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	result := re.ReplaceAllStringFunc(input, func(match string) string {
		code, err := strconv.ParseInt(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})

	re2 := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	result = re2.ReplaceAllStringFunc(result, func(match string) string {
		code, err := strconv.ParseInt(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})

	if result == input {
		return "", fmt.Errorf("no unicode escapes found")
	}
	return result, nil
}

// Base85/Ascii85 decoder
func base85Decoder(input string) (string, error) {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "<~") && strings.HasSuffix(s, "~>") {
		s = s[2 : len(s)-2]
	}

	s = strings.ReplaceAll(s, "z", "!!!!!")

	if len(s) == 0 {
		return "", fmt.Errorf("empty base85 input")
	}

	for _, c := range s {
		if (c < '!' || c > 'u') && c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			return "", fmt.Errorf("invalid base85 character: %c", c)
		}
	}

	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)

	if len(s) == 0 {
		return "", fmt.Errorf("empty base85 input after cleanup")
	}

	var result []byte
	for len(s) > 0 {
		chunkLen := 5
		if len(s) < 5 {
			chunkLen = len(s)
		}
		chunk := s[:chunkLen]
		s = s[chunkLen:]

		// Pad with 'u' (84) if needed
		padded := chunk + strings.Repeat("u", 5-chunkLen)

		var value uint32
		for _, c := range padded {
			if c < '!' || c > 'u' {
				return "", fmt.Errorf("invalid base85 character: %c", c)
			}
			value = value*85 + uint32(c-'!')
		}

		numBytes := chunkLen - 1
		if numBytes < 1 {
			numBytes = 1
		}
		if numBytes > 4 {
			numBytes = 4
		}

		decoded := []byte{
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
		result = append(result, decoded[:numBytes]...)
	}

	if len(result) == 0 {
		return "", fmt.Errorf("no base85 data decoded")
	}

	printable := 0
	for _, b := range result {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	if float64(printable)/float64(len(result)) < 0.5 {
		return "", fmt.Errorf("decoded base85 not printable")
	}

	return string(result), nil
}

func caesarBruteForceDecoder(input string) (string, error) {
	for shift := 1; shift < 26; shift++ {
		if shift == 13 {
			continue
		}

		var result strings.Builder
		hasLetters := false

		for _, r := range input {
			if r >= 'a' && r <= 'z' {
				hasLetters = true
				result.WriteRune('a' + (r-'a'+rune(shift))%26)
			} else if r >= 'A' && r <= 'Z' {
				hasLetters = true
				result.WriteRune('A' + (r-'A'+rune(shift))%26)
			} else {
				result.WriteRune(r)
			}
		}

		if !hasLetters {
			return "", fmt.Errorf("no letters to rotate")
		}

		decoded := result.String()
		// Return first result (BFS will explore all)
		if decoded != input {
			return decoded, nil
		}
	}

	return "", fmt.Errorf("no valid caesar shift found")
}

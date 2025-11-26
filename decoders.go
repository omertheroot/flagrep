package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"regexp"
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
		// add yours here
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

// add yours here

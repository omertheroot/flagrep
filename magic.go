package main

import "bytes"

// MagicSignature defines a file type signature
type MagicSignature struct {
	Name   string
	Magic  []byte
	Offset int // Offset from start of file where magic bytes appear
}

// Common file magic signatures
var magicSignatures = []MagicSignature{
	// Executables
	{Name: "ELF", Magic: []byte{0x7F, 'E', 'L', 'F'}, Offset: 0},
	{Name: "MZ", Magic: []byte{'M', 'Z'}, Offset: 0}, // DOS/Windows PE
	{Name: "MACH-O", Magic: []byte{0xFE, 0xED, 0xFA, 0xCE}, Offset: 0},
	{Name: "MACH-O64", Magic: []byte{0xFE, 0xED, 0xFA, 0xCF}, Offset: 0},

	// Archives
	{Name: "ZIP", Magic: []byte{'P', 'K', 0x03, 0x04}, Offset: 0},
	{Name: "GZIP", Magic: []byte{0x1F, 0x8B}, Offset: 0},
	{Name: "RAR", Magic: []byte{'R', 'a', 'r', '!', 0x1A, 0x07}, Offset: 0},
	{Name: "7Z", Magic: []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, Offset: 0},
	{Name: "TAR", Magic: []byte{'u', 's', 't', 'a', 'r'}, Offset: 257},
	{Name: "XZ", Magic: []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, Offset: 0},
	{Name: "BZIP2", Magic: []byte{'B', 'Z', 'h'}, Offset: 0},

	// Documents
	{Name: "PDF", Magic: []byte{'%', 'P', 'D', 'F'}, Offset: 0},

	// Images
	{Name: "PNG", Magic: []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, Offset: 0},
	{Name: "JPEG", Magic: []byte{0xFF, 0xD8, 0xFF}, Offset: 0},
	{Name: "GIF", Magic: []byte{'G', 'I', 'F', '8'}, Offset: 0},
	{Name: "BMP", Magic: []byte{'B', 'M'}, Offset: 0},
	{Name: "WEBP", Magic: []byte{'R', 'I', 'F', 'F'}, Offset: 0}, // RIFF container

	// Media
	{Name: "MP3", Magic: []byte{0xFF, 0xFB}, Offset: 0},
	{Name: "MP3_ID3", Magic: []byte{'I', 'D', '3'}, Offset: 0},
	{Name: "OGG", Magic: []byte{'O', 'g', 'g', 'S'}, Offset: 0},
	{Name: "FLAC", Magic: []byte{'f', 'L', 'a', 'C'}, Offset: 0},

	// Java
	{Name: "CLASS", Magic: []byte{0xCA, 0xFE, 0xBA, 0xBE}, Offset: 0},
	{Name: "DEX", Magic: []byte{'d', 'e', 'x', '\n'}, Offset: 0},

	// Scripts/Text (shebang)
	{Name: "SCRIPT", Magic: []byte{'#', '!'}, Offset: 0},

	// Databases
	{Name: "SQLITE", Magic: []byte{'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't'}, Offset: 0},
}

// DetectMagic returns the detected file type based on magic bytes
// Returns "unknown" if no match is found
func DetectMagic(data []byte) string {
	for _, sig := range magicSignatures {
		if len(data) < sig.Offset+len(sig.Magic) {
			continue
		}
		if bytes.Equal(data[sig.Offset:sig.Offset+len(sig.Magic)], sig.Magic) {
			return sig.Name
		}
	}
	return "unknown"
}

// MatchesMagicFilter checks if data matches any of the specified magic types
// If filter is empty, returns true (no filtering)
func MatchesMagicFilter(data []byte, filter []string) bool {
	if len(filter) == 0 {
		return true
	}

	detected := DetectMagic(data)
	for _, f := range filter {
		if f == detected {
			return true
		}
	}
	return false
}

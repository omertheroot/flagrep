package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// FileHeader contains parsed header information
type FileHeader struct {
	Type         string // ELF, PE, MACH-O, etc.
	Architecture string // x86, x86_64, ARM, etc.
	Bits         int    // 32 or 64
	Endianness   string // little or big
	Sections     []SectionInfo
	Imports      []string
	Exports      []string
}

// SectionInfo describes a file section
type SectionInfo struct {
	Name        string
	VirtualAddr uint64
	Size        uint64
	Entropy     float64
	Executable  bool
	Writable    bool
	Readable    bool
}

// ParseELFHeader parses an ELF file header
func ParseELFHeader(data []byte) (*FileHeader, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small for ELF header")
	}

	// Check ELF magic
	if !bytes.Equal(data[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		return nil, fmt.Errorf("not an ELF file")
	}

	header := &FileHeader{Type: "ELF"}

	// EI_CLASS (32 or 64 bit)
	switch data[4] {
	case 1:
		header.Bits = 32
	case 2:
		header.Bits = 64
	default:
		return nil, fmt.Errorf("invalid ELF class")
	}

	// EI_DATA (endianness)
	switch data[5] {
	case 1:
		header.Endianness = "little"
	case 2:
		header.Endianness = "big"
	default:
		return nil, fmt.Errorf("invalid ELF endianness")
	}

	// Machine type
	var machine uint16
	if header.Endianness == "little" {
		machine = binary.LittleEndian.Uint16(data[18:20])
	} else {
		machine = binary.BigEndian.Uint16(data[18:20])
	}

	switch machine {
	case 0x03:
		header.Architecture = "x86"
	case 0x3E:
		header.Architecture = "x86_64"
	case 0x28:
		header.Architecture = "ARM"
	case 0xB7:
		header.Architecture = "ARM64"
	case 0x08:
		header.Architecture = "MIPS"
	case 0x14:
		header.Architecture = "PowerPC"
	case 0xF3:
		header.Architecture = "RISC-V"
	default:
		header.Architecture = fmt.Sprintf("unknown(0x%X)", machine)
	}

	// Parse section headers (simplified)
	if header.Bits == 64 && len(data) >= 64 {
		var shoff uint64
		var shnum, shentsize uint16

		if header.Endianness == "little" {
			shoff = binary.LittleEndian.Uint64(data[40:48])
			shentsize = binary.LittleEndian.Uint16(data[58:60])
			shnum = binary.LittleEndian.Uint16(data[60:62])
		} else {
			shoff = binary.BigEndian.Uint64(data[40:48])
			shentsize = binary.BigEndian.Uint16(data[58:60])
			shnum = binary.BigEndian.Uint16(data[60:62])
		}

		// Parse sections if we have enough data
		if shoff > 0 && shoff < uint64(len(data)) && shnum > 0 && shnum < 100 {
			for i := uint16(0); i < shnum && int(shoff)+int(shentsize) <= len(data); i++ {
				offset := int(shoff) + int(i)*int(shentsize)
				if offset+64 > len(data) {
					break
				}

				var shSize, shAddr uint64
				var shFlags uint64

				if header.Endianness == "little" {
					shAddr = binary.LittleEndian.Uint64(data[offset+16 : offset+24])
					shSize = binary.LittleEndian.Uint64(data[offset+32 : offset+40])
					shFlags = binary.LittleEndian.Uint64(data[offset+8 : offset+16])
				} else {
					shAddr = binary.BigEndian.Uint64(data[offset+16 : offset+24])
					shSize = binary.BigEndian.Uint64(data[offset+32 : offset+40])
					shFlags = binary.BigEndian.Uint64(data[offset+8 : offset+16])
				}

				section := SectionInfo{
					VirtualAddr: shAddr,
					Size:        shSize,
					Writable:    shFlags&0x1 != 0,
					Readable:    true,
					Executable:  shFlags&0x4 != 0,
				}
				header.Sections = append(header.Sections, section)
			}
		}
	}

	return header, nil
}

// ParsePEHeader parses a PE (Windows) file header
func ParsePEHeader(data []byte) (*FileHeader, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small for PE header")
	}

	// Check MZ magic
	if !bytes.Equal(data[:2], []byte{'M', 'Z'}) {
		return nil, fmt.Errorf("not a PE file")
	}

	header := &FileHeader{
		Type:       "PE",
		Endianness: "little", // PE is always little-endian
	}

	// Get PE header offset from DOS header
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	if peOffset > uint32(len(data))-4 {
		return nil, fmt.Errorf("invalid PE offset")
	}

	// Check PE signature
	if !bytes.Equal(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return nil, fmt.Errorf("invalid PE signature")
	}

	// Machine type
	coffOffset := peOffset + 4
	if int(coffOffset)+20 > len(data) {
		return nil, fmt.Errorf("truncated COFF header")
	}

	machine := binary.LittleEndian.Uint16(data[coffOffset : coffOffset+2])

	switch machine {
	case 0x014c:
		header.Architecture = "x86"
		header.Bits = 32
	case 0x8664:
		header.Architecture = "x86_64"
		header.Bits = 64
	case 0x01c0, 0x01c4:
		header.Architecture = "ARM"
		header.Bits = 32
	case 0xAA64:
		header.Architecture = "ARM64"
		header.Bits = 64
	default:
		header.Architecture = fmt.Sprintf("unknown(0x%X)", machine)
		header.Bits = 32
	}

	// Number of sections
	numSections := binary.LittleEndian.Uint16(data[coffOffset+2 : coffOffset+4])

	// Optional header size
	optHeaderSize := binary.LittleEndian.Uint16(data[coffOffset+16 : coffOffset+18])

	// Parse sections
	sectionTableOffset := int(coffOffset) + 20 + int(optHeaderSize)
	for i := uint16(0); i < numSections && i < 50; i++ {
		sectOffset := sectionTableOffset + int(i)*40
		if sectOffset+40 > len(data) {
			break
		}

		// Section name (8 bytes, null-padded)
		nameBytes := data[sectOffset : sectOffset+8]
		name := string(bytes.TrimRight(nameBytes, "\x00"))

		virtSize := binary.LittleEndian.Uint32(data[sectOffset+8 : sectOffset+12])
		virtAddr := binary.LittleEndian.Uint32(data[sectOffset+12 : sectOffset+16])
		characteristics := binary.LittleEndian.Uint32(data[sectOffset+36 : sectOffset+40])

		section := SectionInfo{
			Name:        name,
			VirtualAddr: uint64(virtAddr),
			Size:        uint64(virtSize),
			Readable:    characteristics&0x40000000 != 0,
			Writable:    characteristics&0x80000000 != 0,
			Executable:  characteristics&0x20000000 != 0,
		}
		header.Sections = append(header.Sections, section)
	}

	return header, nil
}

// ParseFileHeader attempts to parse any supported file format
func ParseFileHeader(data []byte) (*FileHeader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("file too small")
	}

	// Try ELF
	if bytes.Equal(data[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		return ParseELFHeader(data)
	}

	// Try PE
	if bytes.Equal(data[:2], []byte{'M', 'Z'}) {
		return ParsePEHeader(data)
	}

	// Try Mach-O
	if bytes.Equal(data[:4], []byte{0xFE, 0xED, 0xFA, 0xCE}) ||
		bytes.Equal(data[:4], []byte{0xFE, 0xED, 0xFA, 0xCF}) ||
		bytes.Equal(data[:4], []byte{0xCE, 0xFA, 0xED, 0xFE}) ||
		bytes.Equal(data[:4], []byte{0xCF, 0xFA, 0xED, 0xFE}) {
		return &FileHeader{
			Type:         "Mach-O",
			Architecture: "unknown",
			Bits:         64,
		}, nil
	}

	return nil, fmt.Errorf("unknown file format")
}

// FormatHeader creates a human-readable representation of the header
func FormatHeader(h *FileHeader) string {
	var result bytes.Buffer

	result.WriteString(fmt.Sprintf("Type:         %s\n", h.Type))
	result.WriteString(fmt.Sprintf("Architecture: %s (%d-bit)\n", h.Architecture, h.Bits))
	result.WriteString(fmt.Sprintf("Endianness:   %s\n", h.Endianness))

	if len(h.Sections) > 0 {
		result.WriteString(fmt.Sprintf("\nSections (%d):\n", len(h.Sections)))
		for _, s := range h.Sections {
			flags := ""
			if s.Readable {
				flags += "R"
			}
			if s.Writable {
				flags += "W"
			}
			if s.Executable {
				flags += "X"
			}
			result.WriteString(fmt.Sprintf("  %-12s 0x%08X %8d bytes [%s]\n",
				s.Name, s.VirtualAddr, s.Size, flags))
		}
	}

	return result.String()
}

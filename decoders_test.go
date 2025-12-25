package main

import (
	"testing"
)

func TestDecodersTable(t *testing.T) {
	decoders := getDecoders()

	tests := []struct {
		name    string
		decoder string
		input   string
		want    string
		wantErr bool
	}{
		{"Reverse", "reverse", "olleH", "Hello", false},
		{"SpaceRemoval", "space_removal", "H e l l o", "Hello", false},
		{"Base64", "base64", "SGVsbG8=", "Hello", false},
		{"Base64URL", "base64_url", "SGVsbG8=", "Hello", false},
		{"Base32", "base32", "JBSWY3DP", "Hello", false},
		{"HexWithSpaces", "hex_with_spaces", "48 65 6c 6c 6f", "Hello", false},
		{"HexWithoutSpaces", "hex_without_spaces", "48656c6c6f", "Hello", false},
		{"HexWithPrefix", "hex_with_prefix", "0x48 0x65 0x6c 0x6c 0x6f", "Hello", false},
		{"Rot13", "rot13", "Uryyb", "Hello", false},
		{"Rot47", "rot47", "w6==@", "Hello", false},
		{"Binary", "binary", "01001000", "H", false},
		{"Octal", "octal", "110 145 154 154 157", "Hello", false},
		{"URL", "url", "%48%65%6c%6c%6f", "Hello", false},
		{"HTML", "html", "&lt;", "<", false},
		{"Atbash", "atbash", "Svool", "Hello", false},
		{"Morse", "morse", ".... . .-.. .-.. ---", "HELLO", false},
		{"Unicode", "unicode_escape", "\\u0048\\u0065\\u006c\\u006c\\u006f", "Hello", false},
		// Error cases
		{"Base64 Invalid", "base64", "InvalidBase64!", "", true},
		{"Binary Invalid", "binary", "12345678", "", true},
		{"Octal Invalid", "octal", "999", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoderFunc, ok := decoders[tt.decoder]
			if !ok {
				t.Fatalf("Decoder %s not found", tt.decoder)
			}
			got, err := decoderFunc(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decoder %s error = %v, wantErr %v", tt.decoder, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Decoder %s = %q, want %q", tt.decoder, got, tt.want)
			}
		})
	}
}

func FuzzReverse(f *testing.F) {
	f.Add("Hello")
	f.Add("World")
	f.Fuzz(func(t *testing.T, orig string) {
		rev, _ := reverseDecoder(orig)
		doubleRev, _ := reverseDecoder(rev)
		if orig != doubleRev {
			t.Errorf("Double reverse failed: %q -> %q -> %q", orig, rev, doubleRev)
		}
	})
}

func FuzzBase64(f *testing.F) {
	f.Add("SGVsbG8=")
	f.Add("VGhpcyBpcyBhIHRlc3Q=")
	f.Fuzz(func(t *testing.T, input string) {
		// Just ensure it doesn't panic
		base64Decoder(input)
	})
}

func FuzzRot13(f *testing.F) {
	f.Add("Hello")
	f.Fuzz(func(t *testing.T, orig string) {
		rot, _ := rot13Decoder(orig)
		doubleRot, _ := rot13Decoder(rot)
		if orig != doubleRot {
			t.Errorf("Double ROT13 failed: %q -> %q -> %q", orig, rot, doubleRot)
		}
	})
}

func BenchmarkDecoders(b *testing.B) {
	decoders := getDecoders()
	input := "SGVsbG8gV29ybGQh This is a benchmark string for decoders."

	b.Run("Base64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decoders["base64"](input)
		}
	})

	b.Run("Rot13", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decoders["rot13"](input)
		}
	})

	b.Run("Reverse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decoders["reverse"](input)
		}
	})
}

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSearcher(t *testing.T) {
	// create temp dir
	tmpDir, err := os.MkdirTemp("", "encodedgrep_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// plain
	plainFile := filepath.Join(tmpDir, "plain.txt")
	err = os.WriteFile(plainFile, []byte("This is a secret message"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// base64
	b64File := filepath.Join(tmpDir, "b64.txt")
	encoded := base64.StdEncoding.EncodeToString([]byte("This is a secret message"))
	err = os.WriteFile(b64File, []byte(encoded), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// plain test
	searcher := NewSearcher([]string{plainFile}, "secret", false, false, 1, 2, 20, 20, false)
	err = searcher.Run()
	if err != nil {
		t.Errorf("Searcher failed on plain text: %v", err)
	}

	// base64 test
	searcher = NewSearcher([]string{b64File}, "secret", false, false, 1, 2, 20, 20, false)
	err = searcher.Run()
	if err != nil {
		t.Errorf("Searcher failed on base64 text: %v", err)
	}
}

func TestDecoders(t *testing.T) {
	decoders := getDecoders()

	// Test Reverse
	rev, _ := decoders["reverse"]("hello")
	if rev != "olleh" {
		t.Errorf("Reverse decoder failed: expected olleh, got %s", rev)
	}

	// Test Base64
	b64, _ := decoders["base64"]("aGVsbG8=")
	if b64 != "hello" {
		t.Errorf("Base64 decoder failed: expected hello, got %s", b64)
	}

	// Test ROT13
	rot, _ := decoders["rot13"]("uryyb")
	if rot != "hello" {
		t.Errorf("ROT13 decoder failed: expected hello, got %s", rot)
	}
}

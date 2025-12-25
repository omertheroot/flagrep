package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the configuration values for flagrep
type Config struct {
	Recursive        bool     `json:"recursive"`
	IgnoreCase       bool     `json:"ignore_case"`
	Workers          int      `json:"workers"`
	Depth            int      `json:"depth"`
	Verbose          bool     `json:"verbose"`
	Context          int      `json:"context"`
	BeforeContext    int      `json:"before_context"`
	AfterContext     int      `json:"after_context"`
	UseRegex         bool     `json:"use_regex"`
	JSONOutput       bool     `json:"json_output"`
	ExcludeDirs      []string `json:"exclude_dirs"`
	EntropyThreshold float64  `json:"entropy_threshold"`
	MagicFilter      []string `json:"magic_filter"`
	TUIMode          bool     `json:"tui_mode"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Recursive:        false,
		Workers:          10,
		Depth:            2,
		BeforeContext:    10,
		AfterContext:     30,
		ExcludeDirs:      []string{".git", "node_modules", "__pycache__", ".venv", "venv"},
		EntropyThreshold: 0,
		MagicFilter:      nil,
	}
}

// LoadConfig loads the configuration from standard locations
func LoadConfig() (*Config, error) {
	config := DefaultConfig()

	path := FindConfigFile()
	if path == "" {
		return config, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("could not open config file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return config, fmt.Errorf("could not decode config file: %w", err)
	}

	return config, nil
}

// FindConfigFile looks for a config file in standard locations
func FindConfigFile() string {
	// Check current directory
	if _, err := os.Stat(".flagreprc"); err == nil {
		return ".flagreprc"
	}
	if _, err := os.Stat(".flagrep.json"); err == nil {
		return ".flagrep.json"
	}

	// Check home directory
	home, err := os.UserHomeDir()
	if err == nil {
		paths := []string{
			filepath.Join(home, ".flagreprc"),
			filepath.Join(home, ".flagrep.json"),
			filepath.Join(home, ".config", "flagrep", "config.json"),
		}

		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	return ""
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// CreateSampleConfig creates a sample configuration file
func CreateSampleConfig(path string) error {
	config := DefaultConfig()
	// Add some sample values for better user guidance
	config.ExcludeDirs = append(config.ExcludeDirs, "dist", "build")

	return SaveConfig(config, path)
}

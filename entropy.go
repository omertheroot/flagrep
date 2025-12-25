package main

import "math"

// CalculateEntropy computes the Shannon entropy of the given data.
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func CalculateEntropyString(s string) float64 {
	return CalculateEntropy([]byte(s))
}
func IsHighEntropy(data []byte, threshold float64) bool {
	return CalculateEntropy(data) >= threshold
}

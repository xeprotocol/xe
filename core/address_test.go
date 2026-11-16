package core

import "testing"

func TestValidateAddress(t *testing.T) {
	validLower := "a2673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	validUpper := "A2673B1CB92518FBCD2C578EF297CE79E90BD1E6E0FCA13A50AF1485B86F435D"
	validMixed := "A2673b1cb92518fbcd2c578ef297ce79E90BD1E6E0FCA13a50af1485b86f435d"

	// Valid canonical lowercase
	normalized, err := ValidateAddress(validLower)
	if err != nil {
		t.Fatalf("expected valid address, got err: %v", err)
	}
	if normalized != validLower {
		t.Fatalf("expected %s, got %s", validLower, normalized)
	}

	// Valid uppercase should normalize to lowercase
	normalized, err = ValidateAddress(validUpper)
	if err != nil {
		t.Fatalf("expected valid uppercase address to succeed, got err: %v", err)
	}
	if normalized != validLower {
		t.Fatalf("expected %s, got %s", validLower, normalized)
	}

	// Valid mixed-case should normalize to lowercase
	normalized, err = ValidateAddress(validMixed)
	if err != nil {
		t.Fatalf("expected valid mixed address to succeed, got err: %v", err)
	}
	if normalized != validLower {
		t.Fatalf("expected %s, got %s", validLower, normalized)
	}

	// Leading/trailing whitespace should be trimmed
	normalized, err = ValidateAddress("  " + validLower + " \n")
	if err != nil {
		t.Fatalf("expected address with whitespace to succeed, got err: %v", err)
	}
	if normalized != validLower {
		t.Fatalf("expected %s, got %s", validLower, normalized)
	}

	// Empty string
	if _, err := ValidateAddress(""); err == nil {
		t.Fatal("expected error on empty address")
	}

	// Too short
	if _, err := ValidateAddress("a2673b1c"); err == nil {
		t.Fatal("expected error on short address")
	}

	// Too long (65 chars)
	if _, err := ValidateAddress(validLower + "0"); err == nil {
		t.Fatal("expected error on 65-char address")
	}

	// Non-hex characters
	nonHex := "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
	if _, err := ValidateAddress(nonHex); err == nil {
		t.Fatal("expected error on non-hex address")
	}
}

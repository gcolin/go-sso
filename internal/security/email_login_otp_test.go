package security

import (
	"testing"
	"time"
)

func TestEmailLoginOTPStoreConsumeOnce(t *testing.T) {
	store := NewEmailLoginOTPStore()
	store.Put("jti-1", "a@example.com", "123456", 600)
	email, ok := store.Consume("jti-1", "123456")
	if !ok || email != "a@example.com" {
		t.Fatalf("consume got %q ok=%v", email, ok)
	}
	if _, ok := store.Consume("jti-1", "123456"); ok {
		t.Fatal("expected single-use")
	}
}

func TestEmailLoginOTPStoreWrongCode(t *testing.T) {
	store := NewEmailLoginOTPStore()
	store.Put("jti-2", "a@example.com", "123456", 600)
	if _, ok := store.Consume("jti-2", "000000"); ok {
		t.Fatal("wrong code must fail")
	}
	email, ok := store.Consume("jti-2", "123456")
	if !ok || email != "a@example.com" {
		t.Fatalf("retry with correct code: %q ok=%v", email, ok)
	}
}

func TestEmailLoginOTPStoreExpired(t *testing.T) {
	store := NewEmailLoginOTPStore()
	store.Put("jti-3", "a@example.com", "123456", 1)
	time.Sleep(1100 * time.Millisecond)
	if _, ok := store.Consume("jti-3", "123456"); ok {
		t.Fatal("expired otp must fail")
	}
}

func TestGenerateOTP6(t *testing.T) {
	code, err := GenerateOTP6()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("len=%d code=%q", len(code), code)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit in %q", code)
		}
	}
}

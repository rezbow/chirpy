package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuth(t *testing.T) {
	tests := []struct {
		password string
	}{
		{"password1"},
		{"password2"},
		{"sfdi409@#!@#"},
	}

	for _, tt := range tests {
		hashedPassword := HashPassword(tt.password)
		if err := ComparePassword(hashedPassword, tt.password); err != nil {
			t.Errorf("ComparePassword(%s, %s) = %v", hashedPassword, tt.password, err)
		}
	}
}

func TestJWT(t *testing.T) {
	tests := []struct {
		userId      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration
		shouldFail  bool
	}{
		{uuid.New(), "X2#$!fsdew", time.Second * 2, false},
		{uuid.New(), "X2#$!fsdew", time.Second * -2, true},
	}

	for _, tt := range tests {
		tokenString, err := MakeJWT(tt.userId, tt.tokenSecret, tt.expiresIn)
		if err != nil {
			t.Fatalf("MakeJWT: unexpected returned error %v ", err)
		}
		userId, err := ValidateJWT(tokenString, tt.tokenSecret)
		if tt.shouldFail {
			if err == nil {
				t.Fatalf("ValidateJWT(%s, %s) = %v, expected error", tokenString, tt.tokenSecret, err)
			}
		} else {
			if err != nil {
				t.Fatalf("ValidateJWT(%s, %s) = %v", tokenString, tt.tokenSecret, err)
			}
			if userId.String() != tt.userId.String() {
				t.Fatalf("ValidateJWT(%s, %s) = %v, expected userId %v", tokenString, tt.tokenSecret, userId, tt.userId)
			}
		}
	}
}

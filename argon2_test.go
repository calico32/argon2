package argon2

import "testing"

func TestArgon2(t *testing.T) {
	debug = true

	hash := Hash([]byte("password"))
	if len(hash) == 0 {
		t.Error("Expected non-empty hash")
	}

	if !Verify(hash, []byte("password")) {
		t.Error("Expected verification to succeed for correct password")
	}

	if Verify(hash, []byte("wrongpassword")) {
		t.Error("Expected verification to fail for incorrect password")
	}
}

func TestNewHash(t *testing.T) {
	h := NewHash(2, 64*1024, 1, 32, 32)

	hash := h.Hash([]byte("password"))
	if len(hash) == 0 {
		t.Error("Expected non-empty hash from NewHash")
	}

	if !Verify(hash, []byte("password")) {
		t.Error("Expected verification to succeed for correct password")
	}
}

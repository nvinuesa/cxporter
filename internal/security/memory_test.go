package security

import (
	"bytes"
	"testing"
)

func TestSecureBytes_Zero(t *testing.T) {
	data := []byte("sensitive password")
	sb := FromBytes(data)
	
	// Verify data is set
	if string(sb.Bytes()) != "sensitive password" {
		t.Error("SecureBytes data not set correctly")
	}
	
	// Verify source is cleared
	for _, b := range data {
		if b != 0 {
			t.Error("Source bytes not cleared")
			break
		}
	}
	
	// Zero the secure bytes
	sb.Zero()
	
	// Verify it's zeroed
	if sb.data != nil {
		t.Error("SecureBytes data not nil after Zero()")
	}
}

func TestSecureBytes_String(t *testing.T) {
	sb := FromBytes([]byte("test"))
	if sb.String() != "test" {
		t.Errorf("String() = %q, want %q", sb.String(), "test")
	}
	sb.Zero()
}

func TestSecureBytes_Clone(t *testing.T) {
	original := FromBytes([]byte("original"))
	clone := original.Clone()
	
	if !bytes.Equal(original.Bytes(), clone.Bytes()) {
		t.Error("Clone does not match original")
	}
	
	// Modify clone
	clone.Bytes()[0] = 'X'
	
	// Original should be unchanged
	if original.Bytes()[0] == 'X' {
		t.Error("Modifying clone affected original")
	}
	
	original.Zero()
	clone.Zero()
}

func TestSecureBytes_Equal(t *testing.T) {
	sb1 := FromBytes([]byte("password"))
	sb2 := FromBytes([]byte("password"))
	sb3 := FromBytes([]byte("different"))
	
	if !sb1.Equal(sb2) {
		t.Error("Equal passwords not detected as equal")
	}
	
	if sb1.Equal(sb3) {
		t.Error("Different passwords detected as equal")
	}
	
	sb1.Zero()
	sb2.Zero()
	sb3.Zero()
}

func TestWipe(t *testing.T) {
	data := []byte("sensitive")
	Wipe(&data)
	
	if data != nil {
		t.Error("Wipe did not nil the slice")
	}
}

func TestWipeString(t *testing.T) {
	s := "password"
	WipeString(&s)
	
	if s != "" {
		t.Error("WipeString did not clear string")
	}
}

func TestSecureBytes_Nil(t *testing.T) {
	var sb *SecureBytes
	
	// These should not panic
	sb.Zero()
	if sb.Len() != 0 {
		t.Error("Nil SecureBytes should have length 0")
	}
	if sb.String() != "" {
		t.Error("Nil SecureBytes should have empty string")
	}
	if sb.Bytes() != nil {
		t.Error("Nil SecureBytes should have nil bytes")
	}
}

func BenchmarkSecureBytes_Zero(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		sb := FromBytes(data)
		sb.Zero()
	}
}

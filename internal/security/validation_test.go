package security

import (
	"strings"
	"testing"
)

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxLen    int
		fieldName string
		wantErr   bool
	}{
		{"Valid", "short", 10, "field", false},
		{"Too long", "verylongstring", 5, "field", true},
		{"Exact limit", "exact", 5, "field", false},
		{"Empty", "", 10, "field", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStringLength(tt.input, tt.maxLen, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStringLength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Normal text", "  hello world  ", "hello world"},
		{"With null byte", "hello\x00world", "helloworld"},
		{"With control chars", "hello\x01\x02world", "helloworld"},
		{"With tabs and newlines", "hello\tworld\n", "hello\tworld"},
		{"With BOM", "\ufeffhello", "hello"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeString(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateCredentialID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"Valid UUID", "550e8400-e29b-41d4-a716-446655440000", false},
		{"Valid simple", "cred123", false},
		{"Empty", "", true},
		{"With slash", "cred/123", true},
		{"With backslash", "cred\\123", true},
		{"With parent ref", "cred../123", true},
		{"With colon", "cred:123", true},
		{"With asterisk", "cred*123", true},
		{"Too long", strings.Repeat("a", MaxCredentialIDLength+1), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentialID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentialID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		allowAbsolute bool
		wantErr       bool
	}{
		{"Valid relative", "dir/file.txt", false, false},
		{"Valid absolute allowed", "/tmp/file.txt", true, false},
		{"Absolute not allowed", "/tmp/file.txt", false, true},
		{"With parent ref", "../../../etc/passwd", false, true},
		{"Empty", "", false, true},
		{"Just filename", "file.txt", false, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path, tt.allowAbsolute)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRelativePath(t *testing.T) {
	baseDir := "/home/user/data"
	
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"Valid relative", "subdir/file.txt", false},
		{"Trying to escape", "../../../etc/passwd", true},
		{"Empty", "", true},
		{"Just filename", "file.txt", false},
		{"Nested valid", "a/b/c/file.txt", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRelativePath(tt.path, baseDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRelativePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"Valid HTTP", "http://example.com", false},
		{"Valid HTTPS", "https://example.com/path", false},
		{"With null byte", "http://example.com\x00/path", true},
		{"Too long", "http://" + strings.Repeat("a", MaxURLLength), true},
		{"Empty", "", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"Valid", "example.com", false},
		{"Valid subdomain", "sub.example.com", false},
		{"Valid with hyphen", "my-site.example.com", false},
		{"Empty", "", true},
		{"Too long", strings.Repeat("a", 254), true},
		{"Label too long", strings.Repeat("a", 64) + ".com", true},
		{"Starts with hyphen", "-example.com", true},
		{"Ends with hyphen", "example-.com", true},
		{"Invalid character", "exam ple.com", true},
		{"Empty label", "example..com", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainName(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomainName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRPID(t *testing.T) {
	tests := []struct {
		name    string
		rpID    string
		wantErr bool
	}{
		{"Valid", "example.com", false},
		{"Valid with subdomain", "login.example.com", false},
		{"Empty", "", true},
		{"Invalid format", "not a domain", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRPID(tt.rpID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRPID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAttachmentSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"Valid small", 1024, false},
		{"Valid max", MaxAttachmentSize, false},
		{"Too large", MaxAttachmentSize + 1, true},
		{"Negative", -1, true},
		{"Zero", 0, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttachmentSize(tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttachmentSize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHasDangerousFileExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"Safe PDF", "document.pdf", false},
		{"Safe TXT", "readme.txt", false},
		{"Dangerous EXE", "malware.exe", true},
		{"Dangerous DLL", "library.dll", true},
		{"Dangerous SH", "script.sh", true},
		{"Dangerous BAT", "script.bat", true},
		{"Dangerous PS1", "script.ps1", true},
		{"Case insensitive EXE", "MALWARE.EXE", true},
		{"No extension", "file", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasDangerousFileExtension(tt.filename)
			if got != tt.want {
				t.Errorf("HasDangerousFileExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateCollectionCount(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"Valid small", 10, false},
		{"Valid medium", 500, false},
		{"Valid max", 1000, false},
		{"Too many", 1001, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCollectionCount(tt.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCollectionCount() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateItemCount(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"Valid small", 100, false},
		{"Valid large", 50000, false},
		{"Valid max", 100000, false},
		{"Too many", 100001, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateItemCount(tt.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateItemCount() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkValidateCredentialID(b *testing.B) {
	id := "550e8400-e29b-41d4-a716-446655440000"
	for i := 0; i < b.N; i++ {
		ValidateCredentialID(id)
	}
}

func BenchmarkSanitizeString(b *testing.B) {
	s := "  hello world with some\x00control\x01chars  "
	for i := 0; i < b.N; i++ {
		SanitizeString(s)
	}
}

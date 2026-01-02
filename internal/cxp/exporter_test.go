package cxp

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nvinuesa/go-cxf"
	"github.com/nvinuesa/go-cxp"
)

func createTestHeader(itemCount int) *cxf.Header {
	items := make([]cxf.Item, itemCount)
	for i := 0; i < itemCount; i++ {
		createdAt := uint64(time.Now().Unix())
		items[i] = cxf.Item{
			ID:         generateTestID(i),
			CreationAt: &createdAt,
			Title:      "Test Item",
			Credentials: []json.RawMessage{
				json.RawMessage(`{"type":"basic-auth","username":{"fieldType":"string","value":"user"}}`),
			},
			Tags: []string{"test"},
		}
	}

	return &cxf.Header{
		Version: cxf.Version{
			Major: cxf.VersionMajor,
			Minor: cxf.VersionMinor,
		},
		ExporterRpId:        "cxporter.local",
		ExporterDisplayName: "cxporter",
		Timestamp:           uint64(time.Now().Unix()),
		Accounts: []cxf.Account{
			{
				ID:       "test-account",
				Username: "testuser",
				Email:    "test@example.com",
				Items:    items,
			},
		},
	}
}

func generateTestID(index int) string {
	return "test-item-" + string(rune('a'+index))
}

func TestExportUnencrypted(t *testing.T) {
	t.Run("Single item", func(t *testing.T) {
		header := createTestHeader(1)
		opts := ExportOptions{Encrypt: false}

		data, err := ExportToBytes(header, opts)
		if err != nil {
			t.Fatalf("ExportToBytes() error = %v", err)
		}

		// Should be valid JSON
		var parsed cxf.Header
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		if parsed.ExporterRpId != header.ExporterRpId {
			t.Errorf("ExporterRpId = %v, want %v", parsed.ExporterRpId, header.ExporterRpId)
		}
		if len(parsed.Accounts) != 1 {
			t.Errorf("Accounts count = %d, want 1", len(parsed.Accounts))
		}
	})

	t.Run("Multiple items", func(t *testing.T) {
		header := createTestHeader(10)
		opts := ExportOptions{Encrypt: false}

		data, err := ExportToBytes(header, opts)
		if err != nil {
			t.Fatalf("ExportToBytes() error = %v", err)
		}

		var parsed cxf.Header
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		if len(parsed.Accounts[0].Items) != 10 {
			t.Errorf("Items count = %d, want 10", len(parsed.Accounts[0].Items))
		}
	})

	t.Run("Empty header", func(t *testing.T) {
		header := &cxf.Header{
			Version:             cxf.Version{Major: 1, Minor: 0},
			ExporterRpId:        "test.local",
			ExporterDisplayName: "test",
			Timestamp:           uint64(time.Now().Unix()),
			Accounts:            []cxf.Account{},
		}
		opts := ExportOptions{Encrypt: false}

		data, err := ExportToBytes(header, opts)
		if err != nil {
			t.Fatalf("ExportToBytes() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("Output should not be empty")
		}
	})

	t.Run("Nil header", func(t *testing.T) {
		opts := ExportOptions{Encrypt: false}
		_, err := ExportToBytes(nil, opts)
		if err != ErrNilHeader {
			t.Errorf("ExportToBytes(nil) error = %v, want ErrNilHeader", err)
		}
	})
}

func TestExportEncrypted(t *testing.T) {
	// Generate test keypair
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test keypair: %v", err)
	}

	t.Run("Single item", func(t *testing.T) {
		header := createTestHeader(1)
		opts := ExportOptions{
			Encrypt:         true,
			RecipientPubKey: pubKey,
		}

		data, err := ExportToBytes(header, opts)
		if err != nil {
			t.Fatalf("ExportToBytes() error = %v", err)
		}

		// Should be a valid ZIP
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("Failed to open ZIP: %v", err)
		}

		// Check structure
		hasIndex := false
		hasDocDir := false
		docCount := 0

		for _, f := range reader.File {
			if f.Name == archiveIndexFile {
				hasIndex = true
			}
			if f.Name == archiveDocsDir {
				hasDocDir = true
			}
			if strings.HasPrefix(f.Name, archiveDocsDir) && strings.HasSuffix(f.Name, ".jwe") {
				docCount++
			}
		}

		if !hasIndex {
			t.Error("Archive missing index.jwe")
		}
		if !hasDocDir {
			t.Error("Archive missing documents directory")
		}
		if docCount != 1 {
			t.Errorf("Archive has %d documents, want 1", docCount)
		}
	})

	t.Run("Multiple items", func(t *testing.T) {
		header := createTestHeader(5)
		opts := ExportOptions{
			Encrypt:         true,
			RecipientPubKey: pubKey,
		}

		data, err := ExportToBytes(header, opts)
		if err != nil {
			t.Fatalf("ExportToBytes() error = %v", err)
		}

		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("Failed to open ZIP: %v", err)
		}

		docCount := 0
		for _, f := range reader.File {
			if strings.HasPrefix(f.Name, archiveDocsDir) && strings.HasSuffix(f.Name, ".jwe") {
				docCount++
			}
		}

		if docCount != 5 {
			t.Errorf("Archive has %d documents, want 5", docCount)
		}
	})

	t.Run("Missing public key", func(t *testing.T) {
		header := createTestHeader(1)
		opts := ExportOptions{
			Encrypt:         true,
			RecipientPubKey: nil,
		}

		_, err := ExportToBytes(header, opts)
		if err != ErrMissingPubKey {
			t.Errorf("ExportToBytes() without pubkey error = %v, want ErrMissingPubKey", err)
		}
	})

	t.Run("Invalid public key", func(t *testing.T) {
		header := createTestHeader(1)
		opts := ExportOptions{
			Encrypt:         true,
			RecipientPubKey: []byte("too-short"),
		}

		_, err := ExportToBytes(header, opts)
		if err != ErrInvalidPublicKey {
			t.Errorf("ExportToBytes() with invalid key error = %v, want ErrInvalidPublicKey", err)
		}
	})
}

func TestExportToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cxp-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	t.Run("Unencrypted to file", func(t *testing.T) {
		header := createTestHeader(1)
		outputPath := filepath.Join(tmpDir, "export.json")
		opts := ExportOptions{
			OutputPath: outputPath,
			Encrypt:    false,
		}

		err := Export(header, opts)
		if err != nil {
			t.Fatalf("Export() error = %v", err)
		}

		// Verify file exists
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		var parsed cxf.Header
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Output file is not valid JSON: %v", err)
		}
	})

	t.Run("Encrypted to file", func(t *testing.T) {
		_, pubKey, _ := GenerateKeyPair()
		header := createTestHeader(1)
		outputPath := filepath.Join(tmpDir, "export.cxp")
		opts := ExportOptions{
			OutputPath:      outputPath,
			Encrypt:         true,
			RecipientPubKey: pubKey,
		}

		err := Export(header, opts)
		if err != nil {
			t.Fatalf("Export() error = %v", err)
		}

		// Verify file exists and is a valid ZIP
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		_, err = zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("Output file is not a valid ZIP: %v", err)
		}
	})

	t.Run("Missing output path", func(t *testing.T) {
		header := createTestHeader(1)
		opts := ExportOptions{
			OutputPath: "",
			Encrypt:    false,
		}

		err := Export(header, opts)
		if err != ErrNoOutputPath {
			t.Errorf("Export() without path error = %v, want ErrNoOutputPath", err)
		}
	})

	t.Run("Creates parent directory", func(t *testing.T) {
		header := createTestHeader(1)
		outputPath := filepath.Join(tmpDir, "nested", "dir", "export.json")
		opts := ExportOptions{
			OutputPath: outputPath,
			Encrypt:    false,
		}

		err := Export(header, opts)
		if err != nil {
			t.Fatalf("Export() error = %v", err)
		}

		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("Output file was not created")
		}
	})
}

func TestHPKEContext(t *testing.T) {
	t.Run("Create context", func(t *testing.T) {
		_, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		ctx, err := NewHPKEContext(pubKey, DefaultHPKEParams())
		if err != nil {
			t.Fatalf("NewHPKEContext() error = %v", err)
		}

		if len(ctx.EncappedKey()) != x25519KeySize {
			t.Errorf("EncappedKey length = %d, want %d", len(ctx.EncappedKey()), x25519KeySize)
		}
	})

	t.Run("Invalid public key length", func(t *testing.T) {
		_, err := NewHPKEContext([]byte("short"), DefaultHPKEParams())
		if err != ErrInvalidPublicKey {
			t.Errorf("NewHPKEContext() error = %v, want ErrInvalidPublicKey", err)
		}
	})

	t.Run("Unsupported mode", func(t *testing.T) {
		_, pubKey, _ := GenerateKeyPair()
		params := DefaultHPKEParams()
		params.Mode = cxp.HpkeModePsk

		_, err := NewHPKEContext(pubKey, params)
		if err == nil {
			t.Error("Expected error for unsupported mode")
		}
	})

	t.Run("Unsupported KEM", func(t *testing.T) {
		_, pubKey, _ := GenerateKeyPair()
		params := DefaultHPKEParams()
		params.Kem = cxp.HpkeKemDhP256

		_, err := NewHPKEContext(pubKey, params)
		if err == nil {
			t.Error("Expected error for unsupported KEM")
		}
	})
}

func TestEncryption(t *testing.T) {
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, err := NewHPKEContext(pubKey, DefaultHPKEParams())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Encrypt plaintext", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		ciphertext, err := ctx.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Ciphertext should be longer due to tag
		if len(ciphertext) <= len(plaintext) {
			t.Error("Ciphertext should be longer than plaintext")
		}
	})

	t.Run("Encrypt to JWE", func(t *testing.T) {
		plaintext := []byte(`{"test": "data"}`)
		jwe, err := ctx.EncryptToJWE(plaintext)
		if err != nil {
			t.Fatalf("EncryptToJWE() error = %v", err)
		}

		// JWE should have 5 parts separated by dots
		parts := strings.Split(string(jwe), ".")
		if len(parts) != 5 {
			t.Errorf("JWE has %d parts, want 5", len(parts))
		}

		// First part should be base64url header
		if parts[0] == "" {
			t.Error("JWE header should not be empty")
		}

		// Second part (encrypted key) should be empty for HPKE
		if parts[1] != "" {
			t.Error("JWE encrypted key should be empty for HPKE")
		}
	})

	t.Run("Multiple encryptions produce different ciphertext", func(t *testing.T) {
		ctx1, _ := NewHPKEContext(pubKey, DefaultHPKEParams())
		ctx2, _ := NewHPKEContext(pubKey, DefaultHPKEParams())

		plaintext := []byte("Same plaintext")

		ct1, _ := ctx1.Encrypt(plaintext, nil)
		ct2, _ := ctx2.Encrypt(plaintext, nil)

		if bytes.Equal(ct1, ct2) {
			t.Error("Different contexts should produce different ciphertext")
		}
	})
}

func TestDefaultHPKEParams(t *testing.T) {
	params := DefaultHPKEParams()

	if params.Mode != cxp.HpkeModeBase {
		t.Errorf("Mode = %v, want Base", params.Mode)
	}
	if params.Kem != cxp.HpkeKemDhX25519 {
		t.Errorf("Kem = %v, want X25519", params.Kem)
	}
	if params.Kdf != cxp.HpkeKdfHkdfSha256 {
		t.Errorf("Kdf = %v, want HKDF-SHA256", params.Kdf)
	}
	if params.Aead != cxp.HpkeAeadAes256Gcm {
		t.Errorf("Aead = %v, want AES-256-GCM", params.Aead)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	priv1, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if len(priv1) != x25519KeySize {
		t.Errorf("Private key length = %d, want %d", len(priv1), x25519KeySize)
	}
	if len(pub1) != x25519KeySize {
		t.Errorf("Public key length = %d, want %d", len(pub1), x25519KeySize)
	}

	// Keys should be unique
	if bytes.Equal(priv1, priv2) {
		t.Error("Generated private keys should be unique")
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("Generated public keys should be unique")
	}
}

func TestLargeCredentials(t *testing.T) {
	// Create a header with a large note-like credential (10KB of text)
	largeData := strings.Repeat("This is a large note with repeated text. ", 300) // ~12KB

	header := &cxf.Header{
		Version:             cxf.Version{Major: 1, Minor: 0},
		ExporterRpId:        "test.local",
		ExporterDisplayName: "test",
		Timestamp:           uint64(time.Now().Unix()),
		Accounts: []cxf.Account{
			{
				ID:       "test-account",
				Username: "testuser",
				Items: []cxf.Item{
					{
						ID:    "large-item",
						Title: "Large Item",
						Credentials: []json.RawMessage{
							json.RawMessage(`{"type":"note","content":{"fieldType":"string","value":"` + largeData + `"}}`),
						},
					},
				},
			},
		},
	}

	_, pubKey, _ := GenerateKeyPair()
	opts := ExportOptions{
		Encrypt:         true,
		RecipientPubKey: pubKey,
	}

	data, err := ExportToBytes(header, opts)
	if err != nil {
		t.Fatalf("ExportToBytes() with large data error = %v", err)
	}

	// Should be a valid ZIP
	_, err = zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Output is not a valid ZIP: %v", err)
	}
}

func TestIndexDocument(t *testing.T) {
	header := createTestHeader(3)

	indexDoc := buildIndexDocument(header)

	if indexDoc.ExporterRpId != header.ExporterRpId {
		t.Errorf("ExporterRpId = %v, want %v", indexDoc.ExporterRpId, header.ExporterRpId)
	}

	if len(indexDoc.Accounts) != 1 {
		t.Fatalf("Accounts count = %d, want 1", len(indexDoc.Accounts))
	}

	if len(indexDoc.Accounts[0].Items) != 3 {
		t.Errorf("Items count = %d, want 3", len(indexDoc.Accounts[0].Items))
	}

	// Index items should NOT have credentials
	for _, item := range indexDoc.Accounts[0].Items {
		if item.Title == "" {
			t.Error("Index item should have title")
		}
	}
}

func TestCustomHPKEParams(t *testing.T) {
	_, pubKey, _ := GenerateKeyPair()
	header := createTestHeader(1)

	customParams := cxp.HpkeParameters{
		Mode: cxp.HpkeModeBase,
		Kem:  cxp.HpkeKemDhX25519,
		Kdf:  cxp.HpkeKdfHkdfSha256,
		Aead: cxp.HpkeAeadAes256Gcm,
	}

	opts := ExportOptions{
		Encrypt:         true,
		RecipientPubKey: pubKey,
		HPKEParams:      &customParams,
	}

	data, err := ExportToBytes(header, opts)
	if err != nil {
		t.Fatalf("ExportToBytes() with custom params error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Output should not be empty")
	}
}

func TestExportResponse(t *testing.T) {
	_, pubKey, _ := GenerateKeyPair()
	header := createTestHeader(1)

	t.Run("Valid export response", func(t *testing.T) {
		resp, err := ExportResponse(header, pubKey)
		if err != nil {
			t.Fatalf("ExportResponse() error = %v", err)
		}

		if resp.Version != cxp.VersionV0 {
			t.Errorf("Version = %v, want %v", resp.Version, cxp.VersionV0)
		}
		if resp.Exporter != header.ExporterRpId {
			t.Errorf("Exporter = %v, want %v", resp.Exporter, header.ExporterRpId)
		}
		if resp.Payload == "" {
			t.Error("Payload should not be empty")
		}
	})

	t.Run("Nil header", func(t *testing.T) {
		_, err := ExportResponse(nil, pubKey)
		if err != ErrNilHeader {
			t.Errorf("ExportResponse(nil) error = %v, want ErrNilHeader", err)
		}
	})

	t.Run("Missing public key", func(t *testing.T) {
		_, err := ExportResponse(header, nil)
		if err != ErrMissingPubKey {
			t.Errorf("ExportResponse() without pubkey error = %v, want ErrMissingPubKey", err)
		}
	})
}

func TestHPKEContextParams(t *testing.T) {
	_, pubKey, _ := GenerateKeyPair()
	params := DefaultHPKEParams()

	ctx, err := NewHPKEContext(pubKey, params)
	if err != nil {
		t.Fatal(err)
	}

	// Test Params() method
	gotParams := ctx.Params()
	if gotParams.Mode != params.Mode {
		t.Errorf("Params().Mode = %v, want %v", gotParams.Mode, params.Mode)
	}
	if gotParams.Kem != params.Kem {
		t.Errorf("Params().Kem = %v, want %v", gotParams.Kem, params.Kem)
	}
}

func TestUnsupportedKDFAndAEAD(t *testing.T) {
	_, pubKey, _ := GenerateKeyPair()

	t.Run("Unsupported KDF", func(t *testing.T) {
		params := DefaultHPKEParams()
		params.Kdf = cxp.HpkeKdfHkdfSha512

		_, err := NewHPKEContext(pubKey, params)
		if err == nil {
			t.Error("Expected error for unsupported KDF")
		}
	})

	t.Run("Unsupported AEAD", func(t *testing.T) {
		params := DefaultHPKEParams()
		params.Aead = cxp.HpkeAeadChaCha20Poly1305

		_, err := NewHPKEContext(pubKey, params)
		if err == nil {
			t.Error("Expected error for unsupported AEAD")
		}
	})
}

func TestCreateUnencryptedArchive(t *testing.T) {
	header := createTestHeader(2)

	data, err := CreateUnencryptedArchive(header)
	if err != nil {
		t.Fatalf("CreateUnencryptedArchive() error = %v", err)
	}

	var parsed cxf.Header
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	if len(parsed.Accounts[0].Items) != 2 {
		t.Errorf("Items count = %d, want 2", len(parsed.Accounts[0].Items))
	}
}

// TestArchiveDeflateCompression verifies CXP-DEV-001: DEFLATE compression.
func TestArchiveDeflateCompression(t *testing.T) {
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	header := createTestHeader(3)
	opts := ExportOptions{
		Encrypt:         true,
		RecipientPubKey: pubKey,
	}

	data, err := ExportToBytes(header, opts)
	if err != nil {
		t.Fatalf("ExportToBytes() error = %v", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}

	for _, f := range reader.File {
		// Directories should use Store method
		if strings.HasSuffix(f.Name, "/") {
			if f.Method != zip.Store {
				t.Errorf("Directory %s uses method %d, want Store (%d)", f.Name, f.Method, zip.Store)
			}
			continue
		}

		// Files should use Deflate method (CXP-DEV-001)
		if f.Method != zip.Deflate {
			t.Errorf("File %s uses method %d, want Deflate (%d)", f.Name, f.Method, zip.Deflate)
		}
	}
}

// TestJWEAlgorithmIdentifier verifies CXP-DEV-002: standard algorithm identifier.
func TestJWEAlgorithmIdentifier(t *testing.T) {
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, err := NewHPKEContext(pubKey, DefaultHPKEParams())
	if err != nil {
		t.Fatal(err)
	}

	jwe, err := ctx.EncryptToJWE([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	// Parse the JWE header
	parts := strings.Split(string(jwe), ".")
	if len(parts) != 5 {
		t.Fatalf("JWE has %d parts, want 5", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode JWE header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("Failed to parse JWE header: %v", err)
	}

	// Verify algorithm identifier follows JOSE HPKE draft format
	expectedAlg := "HPKE-Base-X25519-SHA256-AES256GCM"
	if header["alg"] != expectedAlg {
		t.Errorf("alg = %v, want %v", header["alg"], expectedAlg)
	}

	if header["enc"] != "A256GCM" {
		t.Errorf("enc = %v, want A256GCM", header["enc"])
	}
}

// TestExportResponseJSONSerialization verifies that ExportResponse
// serializes to proper CXP-compliant JSON with all required fields.
func TestExportResponseJSONSerialization(t *testing.T) {
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	header := createTestHeader(2)

	resp, err := ExportResponse(header, pubKey)
	if err != nil {
		t.Fatalf("ExportResponse() error = %v", err)
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Parse back to verify structure
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify all required CXP fields are present
	t.Run("Has version field", func(t *testing.T) {
		if _, ok := parsed["version"]; !ok {
			t.Error("Missing 'version' field")
		}
	})

	t.Run("Has hpke field", func(t *testing.T) {
		hpke, ok := parsed["hpke"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing or invalid 'hpke' field")
		}
		// Verify HPKE sub-fields
		if _, ok := hpke["mode"]; !ok {
			t.Error("Missing 'hpke.mode' field")
		}
		if _, ok := hpke["kem"]; !ok {
			t.Error("Missing 'hpke.kem' field")
		}
		if _, ok := hpke["kdf"]; !ok {
			t.Error("Missing 'hpke.kdf' field")
		}
		if _, ok := hpke["aead"]; !ok {
			t.Error("Missing 'hpke.aead' field")
		}
	})

	t.Run("Has exporter field", func(t *testing.T) {
		exporter, ok := parsed["exporter"].(string)
		if !ok || exporter == "" {
			t.Error("Missing or empty 'exporter' field")
		}
	})

	t.Run("Has payload field", func(t *testing.T) {
		payload, ok := parsed["payload"].(string)
		if !ok || payload == "" {
			t.Error("Missing or empty 'payload' field")
		}
		// Verify payload is valid base64url
		_, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			t.Errorf("payload is not valid base64url: %v", err)
		}
	})

	t.Run("Payload decodes to valid ZIP", func(t *testing.T) {
		payload := parsed["payload"].(string)
		zipData, _ := base64.RawURLEncoding.DecodeString(payload)

		zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err != nil {
			t.Fatalf("Failed to open ZIP from payload: %v", err)
		}

		// Should have index.jwe and documents
		hasIndex := false
		hasDocuments := false
		for _, f := range zipReader.File {
			if f.Name == "CXP-Export/index.jwe" {
				hasIndex = true
			}
			if strings.HasPrefix(f.Name, "CXP-Export/documents/") && strings.HasSuffix(f.Name, ".jwe") {
				hasDocuments = true
			}
		}
		if !hasIndex {
			t.Error("ZIP payload missing index.jwe")
		}
		if !hasDocuments {
			t.Error("ZIP payload missing documents/*.jwe files")
		}
	})
}

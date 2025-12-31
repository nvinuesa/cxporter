package cxp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/nvinuesa/go-cxp"
)

// HPKE errors.
var (
	ErrInvalidPublicKey  = errors.New("invalid public key: must be 32 bytes for X25519")
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrUnsupportedParams = errors.New("unsupported HPKE parameters")
)

// HPKE constants per RFC 9180.
const (
	x25519KeySize = 32
	nonceSize     = 12
	tagSize       = 16
)

// HPKEContext holds encryption state for a single export.
type HPKEContext struct {
	params       cxp.HpkeParameters
	sharedSecret []byte
	encappedKey  []byte // Sender's ephemeral public key
	baseNonce    []byte
	seq          uint64
	aead         cipher.AEAD
}

// NewHPKEContext creates encryption context for a recipient's public key.
func NewHPKEContext(recipientPubKey []byte, params cxp.HpkeParameters) (*HPKEContext, error) {
	if len(recipientPubKey) != x25519KeySize {
		return nil, ErrInvalidPublicKey
	}

	// Validate parameters
	if params.Mode != cxp.HpkeModeBase {
		return nil, fmt.Errorf("%w: only base mode supported", ErrUnsupportedParams)
	}
	if params.Kem != cxp.HpkeKemDhX25519 {
		return nil, fmt.Errorf("%w: only X25519 KEM supported", ErrUnsupportedParams)
	}
	if params.Kdf != cxp.HpkeKdfHkdfSha256 {
		return nil, fmt.Errorf("%w: only HKDF-SHA256 KDF supported", ErrUnsupportedParams)
	}
	if params.Aead != cxp.HpkeAeadAes256Gcm {
		return nil, fmt.Errorf("%w: only AES-256-GCM AEAD supported", ErrUnsupportedParams)
	}

	// Generate ephemeral keypair
	ephemeralPrivate := make([]byte, x25519KeySize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Compute ephemeral public key
	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ephemeral public key: %w", err)
	}

	// Compute shared secret via ECDH
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Build HPKE context using KeySchedule
	ctx := &HPKEContext{
		params:      params,
		encappedKey: ephemeralPublic,
	}

	// Key schedule: derive key and nonce from shared secret
	if err := ctx.keySchedule(sharedSecret, ephemeralPublic, recipientPubKey); err != nil {
		return nil, err
	}

	return ctx, nil
}

// keySchedule derives AEAD key and base nonce per RFC 9180.
func (h *HPKEContext) keySchedule(sharedSecret, enc, pkR []byte) error {
	// HPKE suite ID for X25519, HKDF-SHA256, AES-256-GCM
	suiteID := []byte("HPKE")
	suiteID = append(suiteID, 0x00, 0x20) // KEM ID: X25519 (0x0020)
	suiteID = append(suiteID, 0x00, 0x01) // KDF ID: HKDF-SHA256 (0x0001)
	suiteID = append(suiteID, 0x00, 0x02) // AEAD ID: AES-256-GCM (0x0002)

	// ks_context = mode || psk_id_hash || info_hash
	// For base mode with no PSK and empty info:
	pskIDHash := sha256.Sum256(nil)
	infoHash := sha256.Sum256(nil)

	ksContext := []byte{0x00} // mode = base
	ksContext = append(ksContext, pskIDHash[:]...)
	ksContext = append(ksContext, infoHash[:]...)

	// Extract shared secret
	// kem_context = enc || pkR
	kemContext := append(enc, pkR...)

	// shared_secret = ExtractAndExpand(dh, kem_context)
	extractedSecret := hkdfExtract(sharedSecret, suiteID, kemContext)

	// Derive key and nonce
	keySize := 32 // AES-256
	key := hkdfExpandLabel(extractedSecret, suiteID, "key", ksContext, keySize)
	h.baseNonce = hkdfExpandLabel(extractedSecret, suiteID, "base_nonce", ksContext, nonceSize)
	h.sharedSecret = extractedSecret

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	h.aead, err = cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	return nil
}

// hkdfExtract performs HKDF-Extract with labeled secret.
func hkdfExtract(secret, suiteID, context []byte) []byte {
	// labeled_ikm = "HPKE-v1" || suite_id || "shared_secret" || secret
	labeledIKM := []byte("HPKE-v1")
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, []byte("shared_secret")...)
	labeledIKM = append(labeledIKM, secret...)

	// psk_input_hash for base mode (empty PSK)
	pskInputHash := sha256.Sum256(nil)

	// labeled_info for ExtractAndExpand
	labeledInfo := []byte("HPKE-v1")
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte("eae_prk")...)
	labeledInfo = append(labeledInfo, context...)

	// HKDF-Extract with labeled inputs
	reader := hkdf.New(sha256.New, labeledIKM, pskInputHash[:], labeledInfo)
	extracted := make([]byte, 32)
	reader.Read(extracted)
	return extracted
}

// hkdfExpandLabel performs HKDF-Expand with labeled info.
func hkdfExpandLabel(secret, suiteID []byte, label string, context []byte, length int) []byte {
	// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || context
	labeledInfo := make([]byte, 2)
	binary.BigEndian.PutUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, context...)

	reader := hkdf.New(sha256.New, secret, nil, labeledInfo)
	expanded := make([]byte, length)
	reader.Read(expanded)
	return expanded
}

// computeNonce XORs base nonce with sequence number.
func (h *HPKEContext) computeNonce() []byte {
	nonce := make([]byte, nonceSize)
	copy(nonce, h.baseNonce)

	// XOR with sequence number (big-endian)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, h.seq)

	for i := 0; i < 8; i++ {
		nonce[nonceSize-8+i] ^= seqBytes[i]
	}

	return nonce
}

// Encrypt encrypts plaintext using HPKE.
func (h *HPKEContext) Encrypt(plaintext []byte, aad []byte) ([]byte, error) {
	nonce := h.computeNonce()
	h.seq++

	ciphertext := h.aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// EncryptToJWE encrypts and wraps in JWE Compact Serialization format.
func (h *HPKEContext) EncryptToJWE(plaintext []byte) ([]byte, error) {
	// JWE header for HPKE
	header := map[string]interface{}{
		"alg": "HPKE-Base-X25519-SHA256-A256GCM",
		"enc": "A256GCM",
		"epk": map[string]string{
			"kty": "OKP",
			"crv": "X25519",
			"x":   base64.RawURLEncoding.EncodeToString(h.encappedKey),
		},
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWE header: %w", err)
	}

	protectedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encrypt plaintext (AAD is the protected header)
	aad := []byte(protectedHeader)
	ciphertext, err := h.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Split ciphertext and tag
	if len(ciphertext) < tagSize {
		return nil, ErrEncryptionFailed
	}
	ct := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]

	// JWE Compact Serialization: header.encryptedKey.iv.ciphertext.tag
	// For HPKE, encrypted_key is empty (key is derived from epk)
	iv := h.computeNonce()
	h.seq-- // Revert since computeNonce incremented, and we want consistent IV

	jwe := fmt.Sprintf("%s..%s.%s.%s",
		protectedHeader,
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ct),
		base64.RawURLEncoding.EncodeToString(tag),
	)

	return []byte(jwe), nil
}

// EncappedKey returns the encapsulated key (sender's ephemeral public key).
func (h *HPKEContext) EncappedKey() []byte {
	return h.encappedKey
}

// Params returns the HPKE parameters.
func (h *HPKEContext) Params() cxp.HpkeParameters {
	return h.params
}

// DefaultHPKEParams returns recommended HPKE parameters.
func DefaultHPKEParams() cxp.HpkeParameters {
	return cxp.HpkeParameters{
		Mode: cxp.HpkeModeBase,
		Kem:  cxp.HpkeKemDhX25519,
		Kdf:  cxp.HpkeKdfHkdfSha256,
		Aead: cxp.HpkeAeadAes256Gcm,
	}
}

// GenerateKeyPair generates an X25519 key pair for testing.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, x25519KeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

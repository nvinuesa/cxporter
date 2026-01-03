package cxp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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
	ErrHKDFExpandFailed  = errors.New("HKDF expand failed")
)

// HPKE constants per RFC 9180.
const (
	x25519KeySize = 32
	nonceSize     = 12 // Nn for AES-256-GCM
	tagSize       = 16
	keySize       = 32 // Nk for AES-256-GCM
	hashSize      = 32 // Nh for HKDF-SHA256
)

// Suite IDs per RFC 9180
var (
	// KEM suite ID: "KEM" || I2OSP(kem_id, 2)
	kemSuiteID = []byte{0x4b, 0x45, 0x4d, 0x00, 0x20} // "KEM" || 0x0020 (DHKEM X25519)

	// HPKE suite ID: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
	hpkeSuiteID = []byte{0x48, 0x50, 0x4b, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x02}
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

// keySchedule derives AEAD key and base nonce per RFC 9180 Section 5.1.
// This implements the KeyScheduleS (sender) for base mode.
func (h *HPKEContext) keySchedule(dh, enc, pkR []byte) error {
	// Step 1: Compute shared_secret from KEM using ExtractAndExpand
	// Per RFC 9180 Section 4.1: shared_secret = ExtractAndExpand(dh, kem_context)
	kemContext := make([]byte, 0, len(enc)+len(pkR))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR...)

	sharedSecret, err := extractAndExpand(dh, kemContext)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Step 2: KeySchedule per RFC 9180 Section 5.1
	// For base mode: psk = "" and psk_id = ""
	psk := []byte{}
	pskID := []byte{}
	info := []byte{} // Empty info for CXP

	// mode = 0x00 for base mode
	mode := byte(0x00)

	// psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
	pskIDHash, err := labeledExtract(hpkeSuiteID, nil, []byte("psk_id_hash"), pskID)
	if err != nil {
		return fmt.Errorf("failed to compute psk_id_hash: %w", err)
	}

	// info_hash = LabeledExtract("", "info_hash", info)
	infoHash, err := labeledExtract(hpkeSuiteID, nil, []byte("info_hash"), info)
	if err != nil {
		return fmt.Errorf("failed to compute info_hash: %w", err)
	}

	// ks_context = mode || psk_id_hash || info_hash
	ksContext := make([]byte, 0, 1+hashSize+hashSize)
	ksContext = append(ksContext, mode)
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	// secret = LabeledExtract(shared_secret, "secret", psk)
	secret, err := labeledExtract(hpkeSuiteID, sharedSecret, []byte("secret"), psk)
	if err != nil {
		return fmt.Errorf("failed to compute secret: %w", err)
	}

	// key = LabeledExpand(secret, "key", ks_context, Nk)
	key, err := labeledExpand(hpkeSuiteID, secret, []byte("key"), ksContext, keySize)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
	h.baseNonce, err = labeledExpand(hpkeSuiteID, secret, []byte("base_nonce"), ksContext, nonceSize)
	if err != nil {
		return fmt.Errorf("failed to derive base_nonce: %w", err)
	}

	h.sharedSecret = sharedSecret

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

// extractAndExpand implements the KEM's ExtractAndExpand per RFC 9180 Section 4.1.
// shared_secret = ExtractAndExpand(dh, kem_context)
func extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	// eae_prk = LabeledExtract("", "eae_prk", dh)
	eaePRK, err := labeledExtract(kemSuiteID, nil, []byte("eae_prk"), dh)
	if err != nil {
		return nil, err
	}

	// shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
	// For DHKEM(X25519), Nsecret = 32
	return labeledExpand(kemSuiteID, eaePRK, []byte("shared_secret"), kemContext, 32)
}

// labeledExtract implements LabeledExtract per RFC 9180 Section 4.
// LabeledExtract(salt, label, ikm) = Extract(salt, labeled_ikm)
// where labeled_ikm = "HPKE-v1" || suite_id || label || ikm
func labeledExtract(suiteID, salt, label, ikm []byte) ([]byte, error) {
	// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
	labeledIKM := make([]byte, 0, 7+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, []byte("HPKE-v1")...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)

	// HKDF-Extract(salt, labeled_ikm)
	// If salt is nil/empty, use zero-filled salt of hash length
	if len(salt) == 0 {
		salt = make([]byte, hashSize)
	}
	return hkdfExtract(salt, labeledIKM), nil
}

// hkdfExtract performs HKDF-Extract per RFC 5869.
// Extract(salt, IKM) -> PRK
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// labeledExpand implements LabeledExpand per RFC 9180 Section 4.
// LabeledExpand(prk, label, info, L) = Expand(prk, labeled_info, L)
// where labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
func labeledExpand(suiteID, prk, label, info []byte, length int) ([]byte, error) {
	// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
	labeledInfo := make([]byte, 2, 2+7+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)

	// HKDF-Expand(prk, labeled_info, L)
	reader := hkdf.Expand(sha256.New, prk, labeledInfo)
	expanded := make([]byte, length)
	n, err := io.ReadFull(reader, expanded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHKDFExpandFailed, err)
	}
	if n != length {
		return nil, fmt.Errorf("%w: short read", ErrHKDFExpandFailed)
	}
	return expanded, nil
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
// Uses standard JOSE HPKE algorithm identifier per draft-ietf-jose-hpke-encrypt.
func (h *HPKEContext) EncryptToJWE(plaintext []byte) ([]byte, error) {
	// JWE header for HPKE per draft-ietf-jose-hpke-encrypt
	// Format: HPKE-[mode]-[kem]-[kdf]-[aead]
	// - mode: Base (0x00)
	// - kem: X25519 (0x0020)
	// - kdf: HKDF-SHA256 (0x0001)
	// - aead: AES-256-GCM (0x0002)
	header := map[string]any{
		"alg": "HPKE-Base-X25519-SHA256-AES256GCM",
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

	// Compute the IV BEFORE encrypting (captures current sequence number)
	iv := h.computeNonce()

	// Encrypt plaintext (AAD is the protected header)
	// Note: Encrypt() will increment seq, but we already captured the correct IV
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

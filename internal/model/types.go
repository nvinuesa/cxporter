// Package model defines the internal credential data model used across all adapters.
package model

import "fmt"

// CredentialType represents the type of credential being stored.
type CredentialType int

const (
	// TypeBasicAuth represents a basic username/password credential.
	TypeBasicAuth CredentialType = iota
	// TypeTOTP represents a Time-based One-Time Password credential.
	TypeTOTP
	// TypeSSHKey represents an SSH key credential.
	TypeSSHKey
	// TypeNote represents a secure note credential.
	TypeNote
	// TypeCreditCard represents a credit card credential.
	TypeCreditCard
	// TypeIdentity represents an identity/personal info credential.
	TypeIdentity
	// TypeAPIKey represents an API key credential.
	TypeAPIKey
	// TypeWiFi represents a WiFi network credential.
	TypeWiFi
)

// String returns the string representation of the CredentialType.
func (t CredentialType) String() string {
	switch t {
	case TypeBasicAuth:
		return "basic-auth"
	case TypeTOTP:
		return "totp"
	case TypeSSHKey:
		return "ssh-key"
	case TypeNote:
		return "note"
	case TypeCreditCard:
		return "credit-card"
	case TypeIdentity:
		return "identity"
	case TypeAPIKey:
		return "api-key"
	case TypeWiFi:
		return "wifi"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// ParseCredentialType parses a string into a CredentialType.
func ParseCredentialType(s string) (CredentialType, error) {
	switch s {
	case "basic-auth":
		return TypeBasicAuth, nil
	case "totp":
		return TypeTOTP, nil
	case "ssh-key":
		return TypeSSHKey, nil
	case "note":
		return TypeNote, nil
	case "credit-card":
		return TypeCreditCard, nil
	case "identity":
		return TypeIdentity, nil
	case "api-key":
		return TypeAPIKey, nil
	case "wifi":
		return TypeWiFi, nil
	default:
		return TypeBasicAuth, fmt.Errorf("unknown credential type: %s", s)
	}
}

// TOTPAlgorithm represents the hash algorithm used for TOTP.
type TOTPAlgorithm string

const (
	// TOTPAlgorithmSHA1 is the SHA1 algorithm (default).
	TOTPAlgorithmSHA1 TOTPAlgorithm = "SHA1"
	// TOTPAlgorithmSHA256 is the SHA256 algorithm.
	TOTPAlgorithmSHA256 TOTPAlgorithm = "SHA256"
	// TOTPAlgorithmSHA512 is the SHA512 algorithm.
	TOTPAlgorithmSHA512 TOTPAlgorithm = "SHA512"
)

// String returns the lowercase string representation for CXF compatibility.
func (a TOTPAlgorithm) String() string {
	switch a {
	case TOTPAlgorithmSHA1:
		return "sha1"
	case TOTPAlgorithmSHA256:
		return "sha256"
	case TOTPAlgorithmSHA512:
		return "sha512"
	default:
		return "sha1"
	}
}

// SSHKeyType represents the type of SSH key.
type SSHKeyType string

const (
	// SSHKeyTypeEd25519 is an Ed25519 key.
	SSHKeyTypeEd25519 SSHKeyType = "ed25519"
	// SSHKeyTypeRSA is an RSA key.
	SSHKeyTypeRSA SSHKeyType = "rsa"
	// SSHKeyTypeECDSA is an ECDSA key.
	SSHKeyTypeECDSA SSHKeyType = "ecdsa"
	// SSHKeyTypeDSA is a DSA key (deprecated).
	SSHKeyTypeDSA SSHKeyType = "dsa"
)

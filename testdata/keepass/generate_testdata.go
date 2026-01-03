//go:build ignore

// This program generates test KeePass databases for testing.
// Run with: go run generate_testdata.go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

const testPassword = "testpassword123"

func main() {
	// Generate all test databases
	if err := generateBasicDB(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate basic.kdbx: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated basic.kdbx")

	if err := generateTOTPDB(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate totp.kdbx: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated totp.kdbx")

	if err := generateNestedGroupsDB(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate nested_groups.kdbx: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated nested_groups.kdbx")

	if err := generateCompleteDB(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate complete.kdbx: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated complete.kdbx")

	fmt.Println("\nAll test databases generated successfully!")
	fmt.Printf("Password for all databases: %s\n", testPassword)
}

func generateBasicDB() error {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Add basic credential entries
	entry1 := gokeepasslib.NewEntry()
	entry1.Values = append(entry1.Values,
		mkValue("Title", "GitHub"),
		mkValue("UserName", "user@example.com"),
		mkProtectedValue("Password", "gh_secret_123"),
		mkValue("URL", "https://github.com"),
		mkValue("Notes", "Personal GitHub account"),
	)
	entry1.Tags = "development,vcs"

	entry2 := gokeepasslib.NewEntry()
	entry2.Values = append(entry2.Values,
		mkValue("Title", "Gmail"),
		mkValue("UserName", "myemail@gmail.com"),
		mkProtectedValue("Password", "gmail_pass_456"),
		mkValue("URL", "https://mail.google.com"),
		mkValue("Notes", "Primary email account"),
	)
	entry2.Tags = "email,personal"

	entry3 := gokeepasslib.NewEntry()
	entry3.Values = append(entry3.Values,
		mkValue("Title", "AWS Console"),
		mkValue("UserName", "admin"),
		mkProtectedValue("Password", "aws_admin_789"),
		mkValue("URL", "https://console.aws.amazon.com"),
		mkValue("Notes", "Production AWS account"),
	)
	entry3.Tags = "cloud,work"

	rootGroup.Entries = append(rootGroup.Entries, entry1, entry2, entry3)
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveDB(db, "basic.kdbx")
}

func generateTOTPDB() error {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Entry with TOTP via otp field
	entry1 := gokeepasslib.NewEntry()
	entry1.Values = append(entry1.Values,
		mkValue("Title", "Google 2FA"),
		mkValue("UserName", "user@gmail.com"),
		mkProtectedValue("Password", "google_pass"),
		mkValue("URL", "https://accounts.google.com"),
		mkValue("otp", "otpauth://totp/Google:user@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google"),
	)

	// Entry with TOTP via TOTP field (alternate naming)
	entry2 := gokeepasslib.NewEntry()
	entry2.Values = append(entry2.Values,
		mkValue("Title", "Dropbox 2FA"),
		mkValue("UserName", "dropbox_user"),
		mkProtectedValue("Password", "dropbox_pass"),
		mkValue("TOTP", "otpauth://totp/Dropbox:dropbox_user?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Dropbox&algorithm=SHA256&digits=6&period=30"),
	)

	// Entry with raw secret (not otpauth URI)
	entry3 := gokeepasslib.NewEntry()
	entry3.Values = append(entry3.Values,
		mkValue("Title", "Slack 2FA"),
		mkValue("UserName", "slack_user"),
		mkProtectedValue("Password", "slack_pass"),
		mkValue("2fa", "KRUGS4ZANFZSAYJAON2HE2LOM4"),
	)

	// Entry with 8-digit TOTP and 60-second period
	entry4 := gokeepasslib.NewEntry()
	entry4.Values = append(entry4.Values,
		mkValue("Title", "Steam Guard"),
		mkValue("UserName", "steam_user"),
		mkProtectedValue("Password", "steam_pass"),
		mkValue("otp", "otpauth://totp/Steam:steam_user?secret=GEZDGNBVGY3TQOJQ&issuer=Steam&digits=8&period=60"),
	)

	rootGroup.Entries = append(rootGroup.Entries, entry1, entry2, entry3, entry4)
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveDB(db, "totp.kdbx")
}

func generateNestedGroupsDB() error {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Entry in root
	rootEntry := gokeepasslib.NewEntry()
	rootEntry.Values = append(rootEntry.Values,
		mkValue("Title", "Root Level Entry"),
		mkValue("UserName", "root_user"),
		mkProtectedValue("Password", "root_pass"),
	)
	rootGroup.Entries = append(rootGroup.Entries, rootEntry)

	// Work group with subgroups
	workGroup := gokeepasslib.NewGroup()
	workGroup.Name = "Work"

	workEntry := gokeepasslib.NewEntry()
	workEntry.Values = append(workEntry.Values,
		mkValue("Title", "Work Laptop"),
		mkValue("UserName", "employee"),
		mkProtectedValue("Password", "laptop_pass"),
	)
	workGroup.Entries = append(workGroup.Entries, workEntry)

	// Servers subgroup
	serversGroup := gokeepasslib.NewGroup()
	serversGroup.Name = "Servers"

	prodServer := gokeepasslib.NewEntry()
	prodServer.Values = append(prodServer.Values,
		mkValue("Title", "Production Server"),
		mkValue("UserName", "admin"),
		mkProtectedValue("Password", "prod_admin_pass"),
		mkValue("URL", "ssh://prod.example.com"),
	)

	stagingServer := gokeepasslib.NewEntry()
	stagingServer.Values = append(stagingServer.Values,
		mkValue("Title", "Staging Server"),
		mkValue("UserName", "deploy"),
		mkProtectedValue("Password", "staging_deploy_pass"),
		mkValue("URL", "ssh://staging.example.com"),
	)
	serversGroup.Entries = append(serversGroup.Entries, prodServer, stagingServer)

	// Databases subgroup under Servers
	dbGroup := gokeepasslib.NewGroup()
	dbGroup.Name = "Databases"

	dbEntry := gokeepasslib.NewEntry()
	dbEntry.Values = append(dbEntry.Values,
		mkValue("Title", "PostgreSQL Production"),
		mkValue("UserName", "postgres"),
		mkProtectedValue("Password", "pg_super_secret"),
		mkValue("URL", "postgresql://db.example.com:5432"),
	)
	dbGroup.Entries = append(dbGroup.Entries, dbEntry)
	serversGroup.Groups = append(serversGroup.Groups, dbGroup)

	workGroup.Groups = append(workGroup.Groups, serversGroup)

	// Personal group
	personalGroup := gokeepasslib.NewGroup()
	personalGroup.Name = "Personal"

	socialEntry := gokeepasslib.NewEntry()
	socialEntry.Values = append(socialEntry.Values,
		mkValue("Title", "Facebook"),
		mkValue("UserName", "myprofile"),
		mkProtectedValue("Password", "fb_pass"),
		mkValue("URL", "https://facebook.com"),
	)
	personalGroup.Entries = append(personalGroup.Entries, socialEntry)

	rootGroup.Groups = append(rootGroup.Groups, workGroup, personalGroup)
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveDB(db, "nested_groups.kdbx")
}

func generateCompleteDB() error {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(testPassword)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	// Entry with custom fields
	entry1 := gokeepasslib.NewEntry()
	entry1.Values = append(entry1.Values,
		mkValue("Title", "Server with Custom Fields"),
		mkValue("UserName", "admin"),
		mkProtectedValue("Password", "admin123"),
		mkValue("URL", "https://server.example.com"),
		mkValue("Notes", "This entry has custom fields"),
		mkValue("API Key", "sk-abc123def456"),
		mkValue("Secret Token", "tok_xyz789"),
		mkValue("Environment", "production"),
	)
	entry1.Tags = "server,api,production"

	// Entry without password (just URL/notes)
	entry2 := gokeepasslib.NewEntry()
	entry2.Values = append(entry2.Values,
		mkValue("Title", "Documentation Link"),
		mkValue("URL", "https://docs.example.com"),
		mkValue("Notes", "Internal documentation portal"),
	)

	// Entry with minimal data (just title and username)
	entry3 := gokeepasslib.NewEntry()
	entry3.Values = append(entry3.Values,
		mkValue("Title", "Legacy System"),
		mkValue("UserName", "legacy_admin"),
	)

	// Entry with TOTP and custom fields combined
	entry4 := gokeepasslib.NewEntry()
	entry4.Values = append(entry4.Values,
		mkValue("Title", "Full Featured Entry"),
		mkValue("UserName", "superuser"),
		mkProtectedValue("Password", "super_secret_pass"),
		mkValue("URL", "https://secure.example.com"),
		mkValue("Notes", "This entry has everything"),
		mkValue("otp", "otpauth://totp/SecureApp:superuser?secret=JBSWY3DPEHPK3PXP&issuer=SecureApp"),
		mkValue("Backup Codes", "12345-67890\nabcde-fghij"),
		mkValue("Recovery Email", "recovery@example.com"),
	)
	entry4.Tags = "secure,mfa,important"

	rootGroup.Entries = append(rootGroup.Entries, entry1, entry2, entry3, entry4)

	// Add a subgroup with more entries
	bankingGroup := gokeepasslib.NewGroup()
	bankingGroup.Name = "Banking"

	bankEntry := gokeepasslib.NewEntry()
	bankEntry.Values = append(bankEntry.Values,
		mkValue("Title", "Online Banking"),
		mkValue("UserName", "account_holder"),
		mkProtectedValue("Password", "bank_pass_secure"),
		mkValue("URL", "https://bank.example.com"),
		mkValue("Account Number", "1234567890"),
		mkValue("Routing Number", "987654321"),
	)
	bankEntry.Tags = "finance,banking"
	bankingGroup.Entries = append(bankingGroup.Entries, bankEntry)

	rootGroup.Groups = append(rootGroup.Groups, bankingGroup)
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

	return saveDB(db, "complete.kdbx")
}

func mkValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value},
	}
}

func mkProtectedValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content:   value,
			Protected: wrappers.NewBoolWrapper(true),
		},
	}
}

func saveDB(db *gokeepasslib.Database, filename string) error {
	// Set metadata
	now := time.Now()
	db.Content.Meta.DatabaseName = "Test Database - " + filename
	db.Content.Meta.DatabaseNameChanged = &wrappers.TimeWrapper{Time: now}

	// Lock protected entries before saving
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("lock entries: %w", err)
	}

	// Create file
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	// Encode database
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}

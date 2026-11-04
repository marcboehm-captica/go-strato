package strato

import (
	"os"
	"testing"
)

// TestDNSRecordListAddRemove is an integration test that:
// 1. Lists current DNS records
// 2. Adds a test record
// 3. Verifies the record was added
// 4. Removes the test record
// 5. Verifies the record was removed
func TestDNSRecordListAddRemove(t *testing.T) {
	// Get credentials from environment variables
	api := os.Getenv("STRATO_API")
	identifier := os.Getenv("STRATO_IDENTIFIER")
	password := os.Getenv("STRATO_PASSWORD")
	order := os.Getenv("STRATO_ORDER")
	domain := os.Getenv("STRATO_DOMAIN")

	// Fail test if credentials are not provided
	if api == "" || identifier == "" || password == "" || order == "" || domain == "" {
		t.Fatalf("Integration test failed: STRATO_* environment variables not set")
	}

	// Create client
	client, err := NewStratoClient(api, identifier, password, order, domain)
	if err != nil {
		t.Fatalf("Failed to create Strato client: %v", err)
	}

	// Test record to add/remove
	testRecord := DNSRecord{
		Type:   "TXT",
		Prefix: "go-strato-test",
		Value:  "integration-test-value",
	}

	// Step 1: Get initial DNS configuration (LIST)
	t.Log("Step 1: Listing current DNS records...")
	initialConfig, err := client.GetDNSConfiguration()
	if err != nil {
		t.Fatalf("Failed to get initial DNS configuration: %v", err)
	}
	t.Logf("Initial DNS configuration: %d records found", len(initialConfig.Records))

	// Verify test record doesn't already exist
	for _, record := range initialConfig.Records {
		if record == testRecord {
			t.Fatalf("Test record already exists, cannot run integration test")
		}
	}

	// Step 2: Add test record (ADD)
	t.Log("Step 2: Adding test DNS record...")
	initialConfig.Records = append(initialConfig.Records, testRecord)
	err = client.SetDNSConfiguration(initialConfig)
	if err != nil {
		t.Fatalf("Failed to add test record: %v", err)
	}

	// Step 3: Verify record was added (LIST)
	t.Log("Step 3: Verifying test record was added...")
	afterAddConfig, err := client.GetDNSConfiguration()
	if err != nil {
		t.Fatalf("Failed to get DNS configuration after adding record: %v", err)
	}

	recordFound := false
	for _, record := range afterAddConfig.Records {
		if record == testRecord {
			recordFound = true
			break
		}
	}

	if !recordFound {
		t.Fatalf("Test record was not found after adding")
	}
	t.Log("✓ Test record successfully added")

	// Step 4: Remove test record (REMOVE)
	t.Log("Step 4: Removing test DNS record...")
	var updatedRecords []DNSRecord
	for _, record := range afterAddConfig.Records {
		if record != testRecord {
			updatedRecords = append(updatedRecords, record)
		}
	}
	afterAddConfig.Records = updatedRecords

	err = client.SetDNSConfiguration(afterAddConfig)
	if err != nil {
		t.Fatalf("Failed to remove test record: %v", err)
	}

	// Step 5: Verify record was removed (LIST)
	t.Log("Step 5: Verifying test record was removed...")
	finalConfig, err := client.GetDNSConfiguration()
	if err != nil {
		t.Fatalf("Failed to get DNS configuration after removing record: %v", err)
	}

	recordFound = false
	for _, record := range finalConfig.Records {
		if record == testRecord {
			recordFound = true
			break
		}
	}

	if recordFound {
		t.Fatalf("Test record was not removed from configuration")
	}
	t.Log("✓ Test record successfully removed")

	t.Log("✓ Integration test passed: List -> Add -> Remove completed successfully")
}

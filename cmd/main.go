package main

import (
	"flag"

	"github.com/fl0eb/go-strato"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)

	// Parse command-line arguments
	api := flag.String("api", "https://www.strato.de/apps/CustomerService", "Strato API URL")
	identifier := flag.String("identifier", "", "Strato identifier")
	password := flag.String("password", "", "Strato password")
	order := flag.String("order", "", "Package order number to update")
	domain := flag.String("domain", "", "(Sub-)Domain to manage")
	command := flag.String("command", "", "Command to execute: add, remove, or list")
	recordType := flag.String("type", "TXT", "Type of DNS record (default: TXT)")
	recordPrefix := flag.String("prefix", "", "Prefix for the DNS record")
	recordValue := flag.String("value", "", "Value for the DNS record")
	flag.Parse()

	if *identifier == "" || *password == "" || *order == "" || *domain == "" || *command == "" {
		klog.Fatal("All flags --identifier, --password, --order, --domain, and --command are required")
	}

	// Initialize the Strato client
	client, err := strato.NewStratoClient(*api, *identifier, *password, *order, *domain)
	if err != nil {
		klog.Fatalf("Failed to create Strato client: %v", err)
	}

	// Execute command
	switch *command {
	case "list":
		config, err := client.GetDNSConfiguration()
		if err != nil {
			klog.Fatalf("Failed to fetch DNS records: %v", err)
		}
		printConfig(config)
		return

	case "add":
		if *recordType == "" {
			klog.Fatal("--type is required for add command")
		}
		if *recordPrefix == "" {
			klog.Fatal("--prefix is required for add command")
		}
		if *recordValue == "" {
			klog.Fatal("--value is required for add command")
		}
		providedRecord := strato.DNSRecord{
			Type:   *recordType,
			Prefix: *recordPrefix,
			Value:  *recordValue,
		}
		config, err := client.GetDNSConfiguration()
		if err != nil {
			klog.Fatalf("Failed to fetch initial configuration: %v", err)
			return
		}
		klog.V(2).Info("DNS configuration before update:")
		printConfig(config)

		if contains(config.Records, providedRecord) {
			klog.V(2).Infof("Record already exists: Type: '%s', Prefix: '%s', Value: '%s'", providedRecord.Type, providedRecord.Prefix, providedRecord.Value)
			return
		}

		config.Records = append(config.Records, providedRecord)
		if err := client.SetDNSConfiguration(config); err != nil {
			klog.Fatalf("Failed to update DNS records: %v", err)
		}
		config, err = client.GetDNSConfiguration()
		if err != nil {
			klog.Fatalf("Failed to fetch updated configuration: %v", err)
		}
		printConfig(config)
		if !contains(config.Records, providedRecord) {
			klog.Fatalf("Failed to add new record")
			return
		}
		klog.V(2).Info("New record added successfully")
		return
	case "remove":
		if *recordType == "" {
			klog.Fatal("--type is required for add command")
		}
		if *recordPrefix == "" {
			klog.Fatal("--prefix is required for add command")
		}
		if *recordValue == "" {
			klog.Fatal("--value is required for add command")
		}
		providedRecord := strato.DNSRecord{
			Type:   *recordType,
			Prefix: *recordPrefix,
			Value:  *recordValue,
		}
		config, err := client.GetDNSConfiguration()
		if err != nil {
			klog.Fatalf("Failed to fetch initial configuration: %v", err)
		}
		klog.V(2).Info("DNS configuration before update:")
		printConfig(config)

		var updatedRecords []strato.DNSRecord
		for _, record := range config.Records {
			if record.Type != providedRecord.Type || record.Prefix != providedRecord.Prefix || record.Value != providedRecord.Value {
				updatedRecords = append(updatedRecords, record)
			}
		}
		if len(updatedRecords) == len(config.Records) {
			klog.V(2).Infof("Record not found: Type: '%s', Prefix: '%s', Value: '%s'", providedRecord.Type, providedRecord.Prefix, providedRecord.Value)
			return
		}
		config.Records = updatedRecords

		if err := client.SetDNSConfiguration(config); err != nil {
			klog.Fatalf("Failed to update DNS configuration: %v", err)
		}
		config, err = client.GetDNSConfiguration()
		if err != nil {
			klog.Fatalf("Failed to fetch DNS configuration: %v", err)
		}
		klog.V(2).Info("DNS configuration after update:")
		printConfig(config)
		if contains(config.Records, providedRecord) {
			klog.Fatalf("Failed to remove record")
			return
		}
		klog.V(2).Info("Record successfully removed")
		return
	default:
		klog.Fatalf("Invalid command: %s. Use add, remove, or list", *command)
	}
	defer klog.Flush()
}

func printConfig(config strato.DNSConfig) {
	klog.V(2).Info("DMARC Type:", config.DMARCType)
	klog.V(2).Info("SPF Type:", config.SPFType)
	klog.V(2).Info("DNS records:")
	for _, record := range config.Records {
		klog.V(2).Infof("Type: '%s', Prefix: '%s', Value: '%s'", record.Type, record.Prefix, record.Value)
	}
}

func contains(records []strato.DNSRecord, record strato.DNSRecord) bool {
	for _, entry := range records {
		if entry.Type == record.Type && entry.Prefix == record.Prefix && entry.Value == record.Value {
			return true
		}
	}
	return false
}

package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// CiscoRunner orchestrates the Cisco device scanning process
type CiscoRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
	connector     CiscoConnector
	executor      CommandExecutor
	parser        OutputParser
	processor     DataProcessor
}

// NewCiscoRunner creates a new Cisco runner with dependencies
func NewCiscoRunner(assetRepo assetPort.Repo, db *gorm.DB) *CiscoRunner {
	ciscoRepo := storage.NewCiscoRepo(db)

	return &CiscoRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
		connector:     NewSSHConnector(),
		executor:      NewCiscoCommandExecutor(),
		parser:        NewCiscoOutputParser(),
		processor:     NewCiscoDataProcessor(assetRepo, ciscoRepo),
	}
}

// Execute implements the scheduler.Scanner interface
func (r *CiscoRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteCiscoScan(ctx, scanner, scanJobID)
}

// ExecuteCiscoScan runs a Cisco device scan based on scanner configuration
func (r *CiscoRunner) ExecuteCiscoScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("Starting Cisco scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)

	// Create cancellable context and register scan
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	startTime := time.Now()
	config := r.buildScanConfig(scanner, scanJobID)

	// Execute the scan
	result, err := r.performScan(scanCtx, config)
	if err != nil {
		if scanCtx.Err() == context.Canceled {
			log.Printf("Cisco scan was cancelled for job ID: %d", scanJobID)
			return context.Canceled
		}
		log.Printf("Error executing Cisco scan: %v", err)
		return err
	}

	result.ScanDuration = time.Since(startTime)
	result.ScanJobID = scanJobID

	// Process and store results
	return r.processor.ProcessResults(ctx, result, scanner.ID)
}

// buildScanConfig creates scan configuration from scanner domain object (SSH only)
func (r *CiscoRunner) buildScanConfig(scanner scannerDomain.ScannerDomain, scanJobID int64) scannerDomain.CiscoScanConfiguration {
	port := r.getDefaultPort(scanner)

	return scannerDomain.CiscoScanConfiguration{
		Scanner:           scanner,
		ScanJobID:         scanJobID,
		DefaultPort:       port,
		TimeoutSeconds:    30,
		RetryAttempts:     3,
		CollectInterfaces: true,
		CollectVLANs:      true,
		CollectRoutes:     true,
		CollectNeighbors:  true,
		ValidationRules:   scannerDomain.DefaultCiscoValidationRules(),
	}
}

// getDefaultPort returns appropriate default port for SSH protocol
func (r *CiscoRunner) getDefaultPort(scanner scannerDomain.ScannerDomain) string {
	if scanner.Port != "" {
		return scanner.Port
	}
	return "22" 
}

// performScan executes the actual device scan via SSH
func (r *CiscoRunner) performScan(ctx context.Context, config scannerDomain.CiscoScanConfiguration) (*scannerDomain.CiscoScanResult, error) {
	log.Printf("Performing Cisco scan on device: %s:%s using SSH",
		config.Scanner.IP, config.DefaultPort)

	result := &scannerDomain.CiscoScanResult{
		DeviceIP:         config.Scanner.IP,
		ConnectionMethod: "SSH",
		ScanJobID:        config.ScanJobID,
	}

	if strings.ToUpper(config.Scanner.Protocol) != "SSH" {
		return nil, fmt.Errorf("unsupported protocol: %s (only SSH is supported)", config.Scanner.Protocol)
	}

	return r.performSSHScan(ctx, config, result)
}

// performSSHScan handles SSH-based scanning
func (r *CiscoRunner) performSSHScan(ctx context.Context, config scannerDomain.CiscoScanConfiguration, result *scannerDomain.CiscoScanResult) (*scannerDomain.CiscoScanResult, error) {
	// Connect to device
	connection, err := r.connector.Connect(ctx, ConnectConfig{
		Host:     config.Scanner.IP,
		Port:     config.DefaultPort,
		Username: config.Scanner.Username,
		Password: config.Scanner.Password,
		Timeout:  time.Duration(config.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer connection.Close()

	// Execute commands
	output, err := r.executor.ExecuteCommands(ctx, connection, GetDefaultCiscoCommands())
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	// Parse output
	if err := r.parser.ParseOutput(output, result); err != nil {
		return nil, fmt.Errorf("output parsing failed: %w", err)
	}

	log.Printf("Cisco SSH scan completed successfully for device: %s", config.Scanner.IP)
	return result, nil
}

// Cancel and status methods
func (r *CiscoRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

func (r *CiscoRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// Connection represents a connection to a network device
type Connection interface {
	Execute(command string) (string, error)
	ExecuteInteractive(commands []string) (string, error)
	Close() error
}

// CiscoConnector handles SSH connections to Cisco devices
type CiscoConnector interface {
	Connect(ctx context.Context, config ConnectConfig) (Connection, error)
}

// ConnectConfig contains connection parameters
type ConnectConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	Timeout  time.Duration
}

// SSHConnector implements SSH connections
type SSHConnector struct{}

// NewSSHConnector creates a new SSH connector
func NewSSHConnector() *SSHConnector {
	return &SSHConnector{}
}
 
// Connect establishes SSH connection
func (c *SSHConnector) Connect(ctx context.Context, config ConnectConfig) (Connection, error) {
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         config.Timeout,
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, config.Port), sshConfig)
	if err != nil {
		return nil, fmt.Errorf("SSH dial failed: %w", err)
	}

	return &SSHConnection{client: conn}, nil
}

// SSHConnection wraps SSH client with interactive session support
type SSHConnection struct {
	client *ssh.Client
}

// Execute runs a command over SSH using interactive session (for Cisco devices)
func (c *SSHConnection) Execute(command string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// For single commands, use CombinedOutput
	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("command execution failed: %w", err)
	}

	return string(output), nil
}

// ExecuteInteractive runs multiple commands in an interactive shell session
func (c *SSHConnection) ExecuteInteractive(commands []string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up pipes for interactive communication
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	// Start shell
	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait a moment for shell to be ready
	time.Sleep(2 * time.Second)

	// Execute commands with logging
	for i, cmd := range commands {
		log.Printf("Executing command %d/%d: %s", i+1, len(commands), cmd)

		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			log.Printf("Failed to write command %s: %v", cmd, err)
			continue
		}

		// Give more time for each command to execute
		if i == 0 {
			// First command (terminal length 0) needs less time
			time.Sleep(1 * time.Second)
		} else {
			// Other commands may need more time
			time.Sleep(3 * time.Second)
		}
	}

	// Exit gracefully
	log.Printf("Sending exit command")
	stdin.Write([]byte("exit\n"))
	stdin.Close()

	// Read all output with timeout
	var outputBuffer strings.Builder
	buffer := make([]byte, 8192) // Larger buffer

	// Wait for session to complete with timeout
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	// Read output with timeout
	go func() {
		for {
			n, err := stdout.Read(buffer)
			if n > 0 {
				outputBuffer.Write(buffer[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for session completion or timeout
	select {
	case err := <-done:
		if err != nil {
			log.Printf("Session completed with error: %v", err)
		} else {
			log.Printf("Session completed successfully")
		}
	case <-time.After(30 * time.Second):
		log.Printf("Session timed out after 30 seconds")
		session.Close()
	}

	output := outputBuffer.String()
	log.Printf("Total output length: %d bytes", len(output))

	if len(output) > 500 {
		log.Printf("Output preview (first 500 chars): %s", output[:500])
	} else if len(output) > 0 {
		log.Printf("Full output: %s", output)
	} else {
		log.Printf("Warning: No output received from device")
	}

	return output, nil
}

// Close closes the SSH connection
func (c *SSHConnection) Close() error {
	return c.client.Close()
}

// CommandExecutor handles command execution on devices
type CommandExecutor interface {
	ExecuteCommands(ctx context.Context, conn Connection, commands []string) (string, error)
}

// CiscoCommandExecutor executes Cisco IOS commands
type CiscoCommandExecutor struct{}

// NewCiscoCommandExecutor creates a new command executor
func NewCiscoCommandExecutor() *CiscoCommandExecutor {
	return &CiscoCommandExecutor{}
}

// ExecuteCommands executes a list of commands using interactive session for Cisco devices
func (e *CiscoCommandExecutor) ExecuteCommands(ctx context.Context, conn Connection, commands []string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	log.Printf("Executing %d commands in interactive session", len(commands))

	// Use interactive session for Cisco devices
	output, err := conn.ExecuteInteractive(commands)
	if err != nil {
		return "", fmt.Errorf("interactive command execution failed: %w", err)
	}

	log.Printf("Received output length: %d bytes", len(output))
	return output, nil
}

// GetDefaultCiscoCommands returns default command set for Cisco devices
func GetDefaultCiscoCommands() []string {
	return []string{
		"terminal length 0",         // Disable pagination
		"show version",              // System information
		"show interfaces",           // Interface details
		"show vlan brief",           // VLAN information
		"show cdp neighbors detail", // CDP neighbors
		"show ip route",             // Routing table
	}
}

// OutputParser handles parsing of command output
type OutputParser interface {
	ParseOutput(output string, result *scannerDomain.CiscoScanResult) error
}

// CiscoOutputParser parses Cisco IOS command output
type CiscoOutputParser struct{}

// NewCiscoOutputParser creates a new output parser
func NewCiscoOutputParser() *CiscoOutputParser {
	return &CiscoOutputParser{}
}

// ParseOutput parses the raw command output into structured data
func (p *CiscoOutputParser) ParseOutput(output string, result *scannerDomain.CiscoScanResult) error {
	log.Printf("Parsing Cisco command output...")

	result.SystemInfo = p.parseSystemInfo(output)
	result.Interfaces = p.parseInterfaces(output)
	result.VLANs, result.VLANPorts = p.parseVLANs(output) // Updated to get both VLANs and VLAN ports
	result.Neighbors = p.parseNeighbors(output)
	result.RoutingTable = p.parseRoutes(output)

	log.Printf("Parsing completed: %d interfaces, %d VLANs, %d VLAN ports, %d neighbors, %d routes",
		len(result.Interfaces), len(result.VLANs), len(result.VLANPorts), len(result.Neighbors), len(result.RoutingTable))

	return nil
}

// parseSystemInfo extracts system information
func (p *CiscoOutputParser) parseSystemInfo(output string) scannerDomain.CiscoSystemInfo {
	sysInfo := scannerDomain.CiscoSystemInfo{}

	patterns := map[string]*regexp.Regexp{
		"hostname": regexp.MustCompile(`(?m)^(\S+)[>#]`),
		"model":    regexp.MustCompile(`(?i)cisco\s+(\S+)`),
		"uptime":   regexp.MustCompile(`(?i)uptime\s+is\s+([^\n\r]+)`),
	}

	if match := patterns["hostname"].FindStringSubmatch(output); len(match) > 1 {
		sysInfo.Hostname = match[1]
	}
	if match := patterns["model"].FindStringSubmatch(output); len(match) > 1 {
		sysInfo.Model = match[1]
	}
	if match := patterns["uptime"].FindStringSubmatch(output); len(match) > 1 {
		sysInfo.SystemUptime = strings.TrimSpace(match[1])
	}

	return sysInfo
}

// parseInterfaces extracts interface information
func (p *CiscoOutputParser) parseInterfaces(output string) []scannerDomain.CiscoInterface {
	var interfaces []scannerDomain.CiscoInterface

	interfaceRegex := regexp.MustCompile(`(GigabitEthernet\d+/\d+|FastEthernet\d+/\d+|Ethernet\d+/\d+|Vlan\d+) is (up|down|administratively down)`)
	protocolRegex := regexp.MustCompile(`line protocol is (up|down)`)
	ipRegex := regexp.MustCompile(`Internet address is (\d+\.\d+\.\d+\.\d+)/(\d+)`)
	macRegex := regexp.MustCompile(`Hardware is.*address is ([a-fA-F0-9.:]+)`)

	sections := p.splitIntoSections(output, interfaceRegex)

	for _, section := range sections {
		if matches := interfaceRegex.FindStringSubmatch(section); len(matches) >= 3 {
			iface := scannerDomain.CiscoInterface{
				Name:   matches[1],
				Status: matches[2],
			}

			if protocolMatch := protocolRegex.FindStringSubmatch(section); len(protocolMatch) > 1 {
				iface.Protocol = protocolMatch[1]
			}
			if ipMatch := ipRegex.FindStringSubmatch(section); len(ipMatch) > 2 {
				iface.IPAddress = ipMatch[1]
				cidr, _ := strconv.Atoi(ipMatch[2])
				iface.SubnetMask = cidrToSubnetMask(cidr)
			}
			if macMatch := macRegex.FindStringSubmatch(section); len(macMatch) > 1 {
				iface.MacAddress = macMatch[1]
			}

			interfaces = append(interfaces, iface)
		}
	}

	return interfaces
}

func (p *CiscoOutputParser) parseVLANs(output string) ([]scannerDomain.CiscoVLAN, []scannerDomain.CiscoVLANPort) {
	var vlans []scannerDomain.CiscoVLAN
	var vlanPorts []scannerDomain.CiscoVLANPort

	// Split output into lines for processing
	lines := strings.Split(output, "\n")

	// Find the start of VLAN table (look for header)
	vlanTableStart := -1
	for i, line := range lines {
		if strings.Contains(line, "VLAN Name") && strings.Contains(line, "Status") {
			vlanTableStart = i + 1 // Skip the header line
			break
		}
	}

	if vlanTableStart == -1 {
		log.Printf("VLAN table not found in output")
		return vlans, vlanPorts
	}

	// Process VLAN entries
	for i := vlanTableStart; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Skip separator lines
		if strings.Contains(line, "----") {
			continue
		}

		// Check if this is a VLAN entry (starts with a number)
		vlanRegex := regexp.MustCompile(`^(\d+)\s+(\S+)\s+(active|suspended|act/unsup)\s*(.*)`)
		match := vlanRegex.FindStringSubmatch(line)

		if len(match) >= 4 {
			vlanID, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}

			vlan := scannerDomain.CiscoVLAN{
				ID:     vlanID,
				Name:   match[2],
				Status: match[3],
				Type:   "enet",
			}

			// Collect all ports for this VLAN (may span multiple lines)
			allPorts := []string{}
			portsStr := strings.TrimSpace(match[4])

			// Add ports from the current line
			if portsStr != "" && portsStr != "unassigned" {
				ports := strings.Fields(portsStr)
				allPorts = append(allPorts, ports...)
			}

			// Check subsequent lines for continuation of ports
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				if nextLine == "" {
					break
				}

				// If next line starts with a number, it's a new VLAN
				if regexp.MustCompile(`^\d+\s`).MatchString(nextLine) {
					break
				}

				// If the line contains only port names (no VLAN ID), it's a continuation
				portContinuationRegex := regexp.MustCompile(`^[A-Za-z]\w*[\d/,\s]+`)
				if portContinuationRegex.MatchString(nextLine) {
					continuationPorts := strings.Fields(nextLine)
					allPorts = append(allPorts, continuationPorts...)
					i = j // Skip this line in the main loop
				} else {
					break
				}
			}

			// Store ports in VLAN object for backward compatibility
			vlan.Ports = allPorts

			// Create individual VLAN port records
			for _, portName := range allPorts {
				portName = strings.TrimSpace(portName)
				if portName != "" && portName != "unassigned" {
					// Try to determine port type from name
					portType := "access" // default
					if strings.Contains(strings.ToLower(portName), "trunk") {
						portType = "trunk"
					}

					vlanPort := scannerDomain.CiscoVLANPort{
						VlanID:     vlanID,
						VlanName:   match[2],
						PortName:   portName,
						PortType:   portType,
						PortStatus: "active", // Default status
					}
					vlanPorts = append(vlanPorts, vlanPort)
				}
			}

			vlans = append(vlans, vlan)
		}
	}

	log.Printf("Parsed %d VLANs with %d total port assignments", len(vlans), len(vlanPorts))
	return vlans, vlanPorts
}

// parseNeighbors extracts neighbor information
func (p *CiscoOutputParser) parseNeighbors(output string) []scannerDomain.CiscoNeighbor {
	var neighbors []scannerDomain.CiscoNeighbor

	deviceRegex := regexp.MustCompile(`Device ID:\s*([^\n]+)`)
	sections := p.splitIntoSections(output, deviceRegex)

	for _, section := range sections {
		if deviceMatch := deviceRegex.FindStringSubmatch(section); len(deviceMatch) > 1 {
			neighbor := scannerDomain.CiscoNeighbor{
				DeviceID: strings.TrimSpace(deviceMatch[1]),
				Protocol: "CDP",
			}

			patterns := map[string]*regexp.Regexp{
				"platform": regexp.MustCompile(`Platform:\s*([^,\n]+)`),
				"local":    regexp.MustCompile(`Interface:\s*([^,\n]+)`),
				"remote":   regexp.MustCompile(`Port ID \(outgoing port\):\s*([^\n]+)`),
				"ip":       regexp.MustCompile(`IP address:\s*(\d+\.\d+\.\d+\.\d+)`),
			}

			if match := patterns["platform"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.Platform = strings.TrimSpace(match[1])
			}
			if match := patterns["local"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.LocalPort = strings.TrimSpace(match[1])
			}
			if match := patterns["remote"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.RemotePort = strings.TrimSpace(match[1])
			}
			if match := patterns["ip"].FindStringSubmatch(section); len(match) > 1 {
				neighbor.IPAddress = match[1]
			}

			neighbors = append(neighbors, neighbor)
		}
	}

	return neighbors
}

// parseRoutes extracts routing information
func (p *CiscoOutputParser) parseRoutes(output string) []scannerDomain.CiscoRoutingEntry {
	var routes []scannerDomain.CiscoRoutingEntry

	routeRegex := regexp.MustCompile(`(?m)^([CSOEIBD*])\s+(\d+\.\d+\.\d+\.\d+/\d+|\d+\.\d+\.\d+\.\d+)\s+.*?via\s+(\d+\.\d+\.\d+\.\d+).*?(\S+)$`)
	matches := routeRegex.FindAllStringSubmatch(output, -1)

	protocolMap := map[string]string{
		"C": "connected", "S": "static", "O": "ospf", "E": "eigrp",
		"I": "igrp", "B": "bgp", "D": "eigrp", "*": "candidate_default",
	}

	for _, match := range matches {
		if len(match) >= 5 {
			protocol := "unknown"
			if mapped, exists := protocolMap[match[1]]; exists {
				protocol = mapped
			}

			route := scannerDomain.CiscoRoutingEntry{
				Protocol:  protocol,
				Network:   match[2],
				NextHop:   match[3],
				Interface: match[4],
			}

			routes = append(routes, route)
		}
	}

	return routes
}

// splitIntoSections splits output into sections based on regex pattern
func (p *CiscoOutputParser) splitIntoSections(output string, pattern *regexp.Regexp) []string {
	matches := pattern.FindAllStringIndex(output, -1)
	if len(matches) == 0 {
		return []string{output}
	}

	var sections []string
	for i, match := range matches {
		start := match[0]
		var end int
		if i+1 < len(matches) {
			end = matches[i+1][0]
		} else {
			end = len(output)
		}
		sections = append(sections, output[start:end])
	}

	return sections
}

// DataProcessor handles database operations and result processing
type DataProcessor interface {
	ProcessResults(ctx context.Context, result *scannerDomain.CiscoScanResult, scannerID int64) error
}

// CiscoDataProcessor processes and stores Cisco scan results
type CiscoDataProcessor struct {
	assetRepo assetPort.Repo
	ciscoRepo *storage.CiscoRepo
}

// NewCiscoDataProcessor creates a new data processor
func NewCiscoDataProcessor(assetRepo assetPort.Repo, ciscoRepo *storage.CiscoRepo) *CiscoDataProcessor {
	return &CiscoDataProcessor{
		assetRepo: assetRepo,
		ciscoRepo: ciscoRepo,
	}
}

// ProcessResults processes scan results and stores them
func (p *CiscoDataProcessor) ProcessResults(ctx context.Context, result *scannerDomain.CiscoScanResult, scannerID int64) error {
	log.Printf("Processing Cisco scan results for device: %s", result.DeviceIP)

	// Create main device asset
	assetID, err := p.createDeviceAsset(ctx, result)
	if err != nil {
		return fmt.Errorf("failed to create device asset: %w", err)
	}

	result.AssetID = assetID.String()
	result.AssetsCreated++

	// Link asset to scan job
	if err := p.assetRepo.LinkAssetToScanJob(ctx, assetID, result.ScanJobID); err != nil {
		log.Printf("Error linking asset to scan job: %v", err)
	}

	// Get Cisco metadata ID and store related data
	ciscoMetadataID, err := p.ciscoRepo.GetCiscoMetadataIDByScannerID(ctx, scannerID)
	if err != nil {
		return fmt.Errorf("failed to get Cisco metadata ID: %w", err)
	}

	// Store Cisco-specific data
	if err := p.storeRelatedData(ctx, result, assetID, ciscoMetadataID); err != nil {
		log.Printf("Error storing related data: %v", err)
		// Continue processing even if some data fails
	}

	log.Printf("Successfully processed device %s (Asset ID: %s)", result.DeviceIP, assetID)
	return nil
}

// createDeviceAsset creates the main device asset
func (p *CiscoDataProcessor) createDeviceAsset(ctx context.Context, result *scannerDomain.CiscoScanResult) (assetDomain.AssetUUID, error) {
	if result.SystemInfo.ManagementIP == "" {
		result.SystemInfo.ManagementIP = result.DeviceIP
	}

	assetID := uuid.New()

	deviceAsset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        result.SystemInfo.Hostname,
		Hostname:    result.SystemInfo.Hostname,
		Type:        "Network Device",
		Description: fmt.Sprintf("Cisco %s discovered by network scan (Job ID: %d)", result.SystemInfo.Model, result.ScanJobID),
		OSName:      "Cisco IOS",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    p.buildAssetIPs(result, assetID.String()),
	}

	return p.assetRepo.Create(ctx, deviceAsset, "CISCO")
}

// buildAssetIPs creates asset IP records
func (p *CiscoDataProcessor) buildAssetIPs(result *scannerDomain.CiscoScanResult, assetID string) []assetDomain.AssetIP {
	var assetIPs []assetDomain.AssetIP

	// Add management IP
	if result.SystemInfo.ManagementIP != "" {
		assetIPs = append(assetIPs, assetDomain.AssetIP{
			AssetID:    assetID,
			IP:         result.SystemInfo.ManagementIP,
			MACAddress: result.SystemInfo.EthernetMAC,
		})
	}

	// Add interface IPs
	for _, iface := range result.Interfaces {
		if iface.IPAddress != "" && iface.IPAddress != result.SystemInfo.ManagementIP {
			assetIPs = append(assetIPs, assetDomain.AssetIP{
				AssetID:    assetID,
				IP:         iface.IPAddress,
				MACAddress: iface.MacAddress,
			})
		}
	}

	return assetIPs
}

// storeRelatedData stores interfaces, VLANs, neighbors, and routes
func (p *CiscoDataProcessor) storeRelatedData(ctx context.Context, result *scannerDomain.CiscoScanResult, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	if err := p.storeInterfaces(ctx, result.Interfaces, assetID, ciscoMetadataID); err != nil {
		return fmt.Errorf("failed to store interfaces: %w", err)
	}

	if err := p.storeVLANs(ctx, result.VLANs, assetID, ciscoMetadataID); err != nil {
		return fmt.Errorf("failed to store VLANs: %w", err)
	}

	// Store VLAN ports
	if err := p.storeVLANPorts(ctx, result.VLANPorts, assetID, ciscoMetadataID); err != nil {
		return fmt.Errorf("failed to store VLAN ports: %w", err)
	}

	if err := p.storeNeighbors(ctx, result.Neighbors, assetID, ciscoMetadataID); err != nil {
		return fmt.Errorf("failed to store neighbors: %w", err)
	}

	if err := p.storeRoutes(ctx, result.RoutingTable, assetID, ciscoMetadataID); err != nil {
		return fmt.Errorf("failed to store routes: %w", err)
	}

	return nil
}

// Storage methods with error handling
func (p *CiscoDataProcessor) storeInterfaces(ctx context.Context, interfaces []scannerDomain.CiscoInterface, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	if len(interfaces) == 0 {
		return nil
	}

	p.ciscoRepo.MarkExistingCiscoInterfacesDeleted(ctx, assetID, ciscoMetadataID)

	var records []types.CiscoInterface
	now := time.Now()

	for _, iface := range interfaces {
		records = append(records, types.CiscoInterface{
			ID:              uuid.New().String(),
			CiscoMetadataID: ciscoMetadataID,
			AssetID:         assetID.String(),
			Name:            iface.Name,
			Description:     iface.Description,
			IPAddress:       iface.IPAddress,
			SubnetMask:      iface.SubnetMask,
			Status:          iface.Status,
			Protocol:        iface.Protocol,
			MacAddress:      iface.MacAddress,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
	}

	return p.ciscoRepo.StoreCiscoInterfaces(ctx, records)
}

func (p *CiscoDataProcessor) storeVLANs(ctx context.Context, vlans []scannerDomain.CiscoVLAN, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	if len(vlans) == 0 {
		return nil
	}

	p.ciscoRepo.MarkExistingCiscoVLANsDeleted(ctx, assetID, ciscoMetadataID)

	var records []types.CiscoVLAN
	now := time.Now()

	for _, vlan := range vlans {
		records = append(records, types.CiscoVLAN{
			ID:              uuid.New().String(),
			CiscoMetadataID: ciscoMetadataID,
			AssetID:         assetID.String(),
			VlanID:          vlan.ID,
			Name:            vlan.Name,
			Status:          vlan.Status,
			Type:            vlan.Type,
			Parent:          vlan.Parent,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
	}

	return p.ciscoRepo.StoreCiscoVLANs(ctx, records)
}

func (p *CiscoDataProcessor) storeNeighbors(ctx context.Context, neighbors []scannerDomain.CiscoNeighbor, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	if len(neighbors) == 0 {
		return nil
	}

	p.ciscoRepo.MarkExistingCiscoNeighborsDeleted(ctx, assetID, ciscoMetadataID)

	var records []types.CiscoNeighbor
	now := time.Now()

	for _, neighbor := range neighbors {
		records = append(records, types.CiscoNeighbor{
			ID:              uuid.New().String(),
			CiscoMetadataID: ciscoMetadataID,
			AssetID:         assetID.String(),
			DeviceID:        neighbor.DeviceID,
			LocalPort:       neighbor.LocalPort,
			RemotePort:      neighbor.RemotePort,
			Platform:        neighbor.Platform,
			IPAddress:       neighbor.IPAddress,
			Capabilities:    neighbor.Capabilities,
			Software:        neighbor.Software,
			Duplex:          neighbor.Duplex,
			Protocol:        neighbor.Protocol,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
	}

	return p.ciscoRepo.StoreCiscoNeighbors(ctx, records)
}

func (p *CiscoDataProcessor) storeRoutes(ctx context.Context, routes []scannerDomain.CiscoRoutingEntry, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	if len(routes) == 0 {
		return nil
	}

	p.ciscoRepo.MarkExistingCiscoRoutesDeleted(ctx, assetID, ciscoMetadataID)

	var records []types.CiscoRoute
	now := time.Now()

	for _, route := range routes {
		records = append(records, types.CiscoRoute{
			ID:              uuid.New().String(),
			CiscoMetadataID: ciscoMetadataID,
			AssetID:         assetID.String(),
			Network:         route.Network,
			Mask:            route.Mask,
			NextHop:         route.NextHop,
			Interface:       route.Interface,
			Metric:          route.Metric,
			AdminDistance:   route.AdminDistance,
			Protocol:        route.Protocol,
			Age:             route.Age,
			Tag:             route.Tag,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
	}

	return p.ciscoRepo.StoreCiscoRoutes(ctx, records)
}

// cidrToSubnetMask converts CIDR notation to subnet mask
func cidrToSubnetMask(cidr int) string {
	if cidr < 0 || cidr > 32 {
		return ""
	}

	mask := (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xFF,
		(mask>>16)&0xFF,
		(mask>>8)&0xFF,
		mask&0xFF)
}

func (p *CiscoDataProcessor) storeVLANPorts(ctx context.Context, vlanPorts []scannerDomain.CiscoVLANPort, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	if len(vlanPorts) == 0 {
		return nil
	}

	p.ciscoRepo.MarkExistingCiscoVLANPortsDeleted(ctx, assetID, ciscoMetadataID)

	var records []types.CiscoVLANPort
	now := time.Now()

	// First, get all VLANs for this asset to map VLAN IDs to VLAN record IDs
	vlanRecords, err := p.ciscoRepo.GetCiscoVLANsByAssetID(ctx, assetID)
	if err != nil {
		return fmt.Errorf("failed to get VLAN records: %w", err)
	}

	// Create a map of VLAN ID to VLAN record ID
	vlanIDMap := make(map[int]string)
	for _, vlan := range vlanRecords {
		vlanIDMap[vlan.VlanID] = vlan.ID
	}

	for _, vlanPort := range vlanPorts {
		// Try to match the interface by name
		var ciscoInterfaceID *string
		interfaces, err := p.ciscoRepo.GetCiscoInterfacesByAssetID(ctx, assetID)
		if err == nil {
			for _, iface := range interfaces {
				if strings.EqualFold(iface.Name, vlanPort.PortName) {
					ciscoInterfaceID = &iface.ID
					break
				}
			}
		}

		// Get the VLAN record ID
		ciscoVLANID, exists := vlanIDMap[vlanPort.VlanID]
		if !exists {
			log.Printf("Warning: VLAN ID %d not found for port %s", vlanPort.VlanID, vlanPort.PortName)
			continue
		}

		records = append(records, types.CiscoVLANPort{
			ID:               uuid.New().String(),
			CiscoMetadataID:  ciscoMetadataID,
			AssetID:          assetID.String(),
			CiscoVLANID:      ciscoVLANID,
			CiscoInterfaceID: ciscoInterfaceID,
			VlanID:           vlanPort.VlanID,
			PortName:         vlanPort.PortName,
			PortType:         vlanPort.PortType,
			PortStatus:       vlanPort.PortStatus,
			CreatedAt:        now,
			UpdatedAt:        now,
		})
	}

	return p.ciscoRepo.StoreCiscoVLANPorts(ctx, records)
}

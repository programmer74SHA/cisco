package types

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// Base tables (no dependencies)
type Vendors struct {
	ID         uint      `gorm:"primaryKey;autoIncrement"`
	VendorName string    `gorm:"size:100;uniqueIndex;not null"`
	VendorCode string    `gorm:"size:20;uniqueIndex;not null"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`

	// Relationships
	Assets []Assets `gorm:"foreignKey:VendorID"`
}

func (Vendors) TableName() string {
	return "vendors"
}

type InterfaceTypes struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TypeName    string `gorm:"size:50;uniqueIndex;not null"`
	Description string `gorm:"size:255"`

	// Relationships
	Interfaces []Interfaces `gorm:"foreignKey:InterfaceTypeID"`
}

func (InterfaceTypes) TableName() string {
	return "interface_types"
}

// Assets table (depends on vendors)
type Assets struct {
	ID               string     `gorm:"column:id;size:50;primaryKey"`
	VendorID         uint       `gorm:"not null;index"`
	Name             string     `gorm:"size:255"`
	Domain           string     `gorm:"size:255"`
	Hostname         string     `gorm:"size:255"`
	OSName           string     `gorm:"size:100;column:os_name"`
	OSVersion        string     `gorm:"size:100;column:os_version"`
	Description      string     `gorm:"type:text"`
	AssetType        string     `gorm:"size:50;default:'firewall';column:asset_type"`
	DiscoveredBy     *string    `gorm:"column:discovered_by;size:255"`
	Risk             string     `gorm:"type:enum('low','medium','high','critical');default:'medium'"`
	LoggingCompleted bool       `gorm:"default:false;column:logging_completed"`
	AssetValue       float64    `gorm:"type:decimal(15,2);default:0.00;column:asset_value"`
	CreatedAt        time.Time  `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt        time.Time  `gorm:"autoUpdateTime;column:updated_at"`
	DeletedAt        *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Vendor          Vendors           `gorm:"foreignKey:VendorID"`
	FirewallDetails []FirewallDetails `gorm:"foreignKey:AssetID"`
	AssetIPs        []AssetIPs        `gorm:"foreignKey:AssetID"`
	AssetScanJobs   []AssetScanJob    `gorm:"foreignKey:AssetID"`
	Ports           []Port            `gorm:"foreignKey:AssetID"`
	VMwareVMs       []VMwareVM        `gorm:"foreignKey:AssetID"`
	Interfaces      []Interfaces      `gorm:"foreignKey:AssetID"`
}

func (Assets) TableName() string {
	return "assets"
}

// Unified Interfaces table (supports multiple scanner types)
type Interfaces struct {
	ID              string  `gorm:"column:id;size:50;primaryKey"`
	InterfaceName   string  `gorm:"size:100;not null"`
	InterfaceTypeID uint    `gorm:"not null;index"`
	AssetID         *string `gorm:"size:50;index"`
	ScannerType     string  `gorm:"size:50;not null"` // 'cisco', 'firewall', etc.
	CiscoMetadataID *int64  `gorm:"index"`            // For Cisco relationships

	// Common interface fields
	Description       string `gorm:"type:text"`
	IPAddress         string `gorm:"size:45"`
	SubnetMask        string `gorm:"size:45"`
	OperationalStatus string `gorm:"type:enum('up','down','unknown');default:'unknown'"`
	AdminStatus       string `gorm:"type:enum('up','down');default:'up'"`
	MacAddress        string `gorm:"size:17"`
	Protocol          string `gorm:"size:50"`

	// VLAN support
	VLANId     *int   `gorm:"column:vlan_id"`
	PortType   string `gorm:"size:50"` // For VLAN ports: 'access', 'trunk', etc.
	PortStatus string `gorm:"size:50"` // For VLAN ports

	// Firewall-specific fields
	VirtualRouter     string  `gorm:"size:100"`
	VirtualSystem     string  `gorm:"size:100"`
	ParentInterfaceID *string `gorm:"size:50;index"` // Self-reference for sub-interfaces

	// Vendor-specific configuration (JSON)
	VendorSpecificConfig string `gorm:"type:json"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`

	// Relationships
	Asset           *Assets        `gorm:"foreignKey:AssetID"`
	InterfaceType   InterfaceTypes `gorm:"foreignKey:InterfaceTypeID"`
	ParentInterface *Interfaces    `gorm:"foreignKey:ParentInterfaceID"` // Self-reference
	SubInterfaces   []Interfaces   `gorm:"foreignKey:ParentInterfaceID"`
	VLANs           []VLANs        `gorm:"foreignKey:ParentInterfaceID"`
	ZoneDetails     []ZoneDetails  `gorm:"foreignKey:InterfaceID"` // Updated field name
}

func (Interfaces) TableName() string {
	return "interfaces"
}

// Unified VLANs table (supports multiple scanner types)
type VLANs struct {
	ID                string `gorm:"column:id;size:50;primaryKey"`
	VLANID            int    `gorm:"not null;column:vlan_id"`
	VLANName          string `gorm:"size:100"`
	Description       string `gorm:"type:text"`
	IsNative          bool   `gorm:"default:false"`
	ParentInterfaceID string `gorm:"not null;index"`
	ScannerType       string `gorm:"size:50;not null"` // 'cisco', 'firewall', etc.
	CiscoMetadataID   *int64 `gorm:"index"`            // For Cisco relationships

	// Cisco-specific fields
	Status string `gorm:"size:50"`               // 'active', 'suspended', etc.
	Type   string `gorm:"size:50"`               // 'enet', etc.
	Parent *int   `gorm:"column:parent_vlan_id"` // Parent VLAN ID

	// Vendor-specific configuration (JSON)
	VendorSpecificConfig string `gorm:"type:json"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`

	// Relationships
	ParentInterface Interfaces    `gorm:"foreignKey:ParentInterfaceID"`
	ZoneDetails     []ZoneDetails `gorm:"foreignKey:VLANTableID"`
}

func (VLANs) TableName() string {
	return "vlans"
}

// Firewall details (depends on assets)
type FirewallDetails struct {
	ID              string `gorm:"column:id;size:50;primaryKey"`
	AssetID         string `gorm:"not null;uniqueIndex"`
	Model           string `gorm:"size:100"`
	FirmwareVersion string `gorm:"size:100"`
	SerialNumber    string `gorm:"size:100"`
	IsHAEnabled     bool   `gorm:"default:false"`
	HARole          string `gorm:"type:enum('active','passive','standalone');default:'standalone'"`
	ManagementIP    string `gorm:"size:45;not null"`
	SiteName        string `gorm:"size:255"`
	Location        string `gorm:"size:255"`
	Status          string `gorm:"type:enum('active','inactive','maintenance');default:'active'"`
	LastSync        *time.Time
	SyncStatus      string    `gorm:"type:enum('success','failed','pending');default:'pending'"`
	CreatedAt       time.Time `gorm:"autoCreateTime"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime"`

	// Relationships
	Asset    Assets           `gorm:"foreignKey:AssetID"`
	Policies []FirewallPolicy `gorm:"foreignKey:FirewallDetailsID"`
}

func (FirewallDetails) TableName() string {
	return "firewall_details"
}

// Zones table (independent)
type Zones struct {
	ID                    string    `gorm:"column:id;size:50;primaryKey"`
	ZoneName              string    `gorm:"size:100;not null;uniqueIndex"`
	ZoneType              string    `gorm:"type:enum('security','virtual_router','context','vdom','vsys');default:'security'"`
	VendorZoneType        string    `gorm:"size:50"`
	Description           string    `gorm:"type:text"`
	ZoneMode              string    `gorm:"type:enum('layer3','layer2','virtual-wire','tap');default:'layer3'"`
	IntrazoneAction       string    `gorm:"type:enum('allow','deny');default:'allow'"`
	ZoneProtectionProfile string    `gorm:"size:100"`
	LogSetting            string    `gorm:"size:100"`
	CreatedAt             time.Time `gorm:"autoCreateTime"`
	UpdatedAt             time.Time `gorm:"autoUpdateTime"`

	// Relationships
	ZoneDetails []ZoneDetails    `gorm:"foreignKey:ZoneID"`
	SrcPolicies []FirewallPolicy `gorm:"foreignKey:SrcZoneID"`
	DstPolicies []FirewallPolicy `gorm:"foreignKey:DstZoneID"`
}

func (Zones) TableName() string {
	return "zones"
}

// Asset IPs (depends on assets)
type AssetIPs struct {
	ID          string     `gorm:"column:id;size:50;primaryKey"`
	AssetID     string     `gorm:"not null;index"`
	InterfaceID string     `gorm:"not null;index"` // Generic interface ID - can reference different tables
	IPAddress   string     `gorm:"size:45;not null;column:ip_address"`
	MacAddress  string     `gorm:"size:17;column:mac_address"`
	CIDRPrefix  *int       `gorm:"column:cidr_prefix"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   *time.Time `gorm:"autoUpdateTime"`
	DeletedAt   *time.Time `gorm:"index"`

	// Relationships
	Asset Assets `gorm:"foreignKey:AssetID"`
}

func (AssetIPs) TableName() string {
	return "asset_ips"
}

// Zone details (junction table - depends on zones, interfaces, and vlans)
type ZoneDetails struct {
	ID          string `gorm:"column:id;size:50;primaryKey"`
	ZoneID      string `gorm:"not null;index"`
	InterfaceID string `gorm:"not null;index"`                // Updated field name
	VLANTableID string `gorm:"not null;index;column:vlan_id"` // References vlans.id

	// Legacy firewall support
	FirewallInterfaceID string `gorm:"index"` // For backward compatibility

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`

	// Relationships
	Zone      Zones      `gorm:"foreignKey:ZoneID"`
	Interface Interfaces `gorm:"foreignKey:InterfaceID"`
	VLAN      VLANs      `gorm:"foreignKey:VLANTableID"` // References vlans.id
}

func (ZoneDetails) TableName() string {
	return "zone_details"
}

// Firewall policies (depends on firewall_details and zones)
type FirewallPolicy struct {
	ID                   string    `gorm:"column:id;size:50;primaryKey"`
	FirewallDetailsID    string    `gorm:"not null;index"`
	PolicyName           string    `gorm:"size:255"`
	PolicyID             *int      `gorm:"index"`
	SrcZoneID            *string   `gorm:"index"`
	DstZoneID            *string   `gorm:"index"`
	Action               string    `gorm:"type:enum('allow','deny','drop','reject','tunnel');default:'deny'"`
	PolicyType           string    `gorm:"type:enum('security','nat','qos','decryption');default:'security'"`
	Status               string    `gorm:"type:enum('enabled','disabled');default:'enabled'"`
	RuleOrder            *int      `gorm:"index"`
	VendorSpecificConfig string    `gorm:"type:json"`
	CreatedAt            time.Time `gorm:"autoCreateTime"`
	UpdatedAt            time.Time `gorm:"autoUpdateTime"`

	// Relationships
	FirewallDetails FirewallDetails `gorm:"foreignKey:FirewallDetailsID"`
	SrcZone         *Zones          `gorm:"foreignKey:SrcZoneID"`
	DstZone         *Zones          `gorm:"foreignKey:DstZoneID"`
}

func (FirewallPolicy) TableName() string {
	return "firewall_policy"
}

// Keep your existing Port and VMwareVM types...
type Port struct {
	ID             string     `gorm:"column:id;size:50;primaryKey"`
	AssetID        string     `gorm:"column:asset_id;not null"`
	PortNumber     int        `gorm:"column:port_number;not null"`
	Protocol       string     `gorm:"column:protocol;type:enum('TCP','UDP');not null"`
	State          string     `gorm:"column:state;type:enum('Up','Down','Unknown');not null"`
	ServiceName    *string    `gorm:"column:service_name;size:100"`
	ServiceVersion *string    `gorm:"column:service_version;size:100"`
	Description    *string    `gorm:"column:description;size:500"`
	DiscoveredAt   time.Time  `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt      *time.Time `gorm:"column:deleted_at;type:datetime"`

	Asset Assets `gorm:"foreignKey:AssetID"`
}

func (Port) TableName() string {
	return "ports"
}

type VMwareVM struct {
	VMID         string    `gorm:"column:vm_id;size:50;primaryKey"`
	AssetID      string    `gorm:"column:asset_id;not null"`
	VMName       string    `gorm:"column:vm_name;size:255;not null"`
	Hypervisor   string    `gorm:"column:hypervisor;size:100;not null"`
	CPUCount     int32     `gorm:"column:cpu_count;not null"`
	MemoryMB     int32     `gorm:"column:memory_mb;not null"`
	DiskSizeGB   int       `gorm:"column:disk_size_gb;not null"`
	PowerState   string    `gorm:"column:power_state;type:enum('On','Off','Suspended');not null"`
	LastSyncedAt time.Time `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Assets `gorm:"foreignKey:AssetID"`
}

func (VMwareVM) TableName() string {
	return "vmware_vms"
}

// Add unique constraints
type UniqueConstraints struct{}

func (u UniqueConstraints) ApplyConstraints(db *gorm.DB) error {
	// Add unique constraint for asset name and hostname combination
	if err := db.Exec("ALTER TABLE assets ADD CONSTRAINT unique_asset UNIQUE (name, hostname)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for interface and IP combination
	if err := db.Exec("ALTER TABLE asset_ips ADD CONSTRAINT unique_ip_per_interface UNIQUE (interface_id, ip_address)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for parent interface and VLAN ID
	if err := db.Exec("ALTER TABLE vlans ADD CONSTRAINT unique_vlan UNIQUE (parent_interface_id, vlan_id)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for zone, interface, and VLAN combination
	if err := db.Exec("ALTER TABLE zone_details ADD CONSTRAINT unique_zone_interface_vlan UNIQUE (zone_id, interface_id, vlan_id)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	return nil
}

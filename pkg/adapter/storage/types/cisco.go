package types

import (
	"time"
)

// CiscoMetadata represents Cisco device metadata in the database
type CiscoMetadata struct {
	ID         int64   `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID  int64   `gorm:"column:scanner_id;not null"`
	IP         string  `gorm:"column:ip;size:50;not null"`
	Port       string  `gorm:"column:port;size:50;not null"`
	Username   string  `gorm:"column:username;size:50;not null"`
	Password   string  `gorm:"column:password;size:200;not null"`
	Protocol   string  `gorm:"column:protocol;size:20;not null"` // SSH
	SSHKeyPath *string `gorm:"column:ssh_key_path;size:500"`
	DeviceType string  `gorm:"column:device_type;size:50;default:'switch'"`

	// Scanning options
	CollectInterfaces bool `gorm:"column:collect_interfaces;default:true"`
	CollectVLANs      bool `gorm:"column:collect_vlans;default:true"`
	CollectRoutes     bool `gorm:"column:collect_routes;default:true"`
	CollectNeighbors  bool `gorm:"column:collect_neighbors;default:true"`

	// Connection settings
	ConnectionTimeout int `gorm:"column:connection_timeout;default:30"`
	CommandTimeout    int `gorm:"column:command_timeout;default:10"`
	MaxRetries        int `gorm:"column:max_retries;default:3"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`

	CiscoInterfaces []CiscoInterface `gorm:"foreignKey:CiscoMetadataID"`
	CiscoVLANs      []CiscoVLAN      `gorm:"foreignKey:CiscoMetadataID"`
	CiscoVRFs       []CiscoVRF       `gorm:"foreignKey:CiscoMetadataID"`
	CiscoRoutes     []CiscoRoute     `gorm:"foreignKey:CiscoMetadataID"`
	CiscoNeighbors  []CiscoNeighbor  `gorm:"foreignKey:CiscoMetadataID"`
	CiscoVLANPorts  []CiscoVLANPort  `gorm:"foreignKey:CiscoMetadataID"`
}

func (CiscoMetadata) TableName() string {
	return "cisco_metadata"
}

// CiscoInterface represents a Cisco network interface in the database
type CiscoInterface struct {
	ID              string    `gorm:"column:id;size:50;primaryKey"`
	CiscoMetadataID int64     `gorm:"column:cisco_metadata_id;not null;index"`
	AssetID         string    `gorm:"column:asset_id;not null;index"`
	Name            string    `gorm:"column:name;size:100;not null"`
	Description     string    `gorm:"column:description;size:500"`
	IPAddress       string    `gorm:"column:ip_address;size:45"`
	SubnetMask      string    `gorm:"column:subnet_mask;size:45"`
	Status          string    `gorm:"column:status;size:50"`   // up/down/administratively down
	Protocol        string    `gorm:"column:protocol;size:50"` // up/down
	MacAddress      string    `gorm:"column:mac_address;size:17"`
	CreatedAt       time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	CiscoMetadata CiscoMetadata   `gorm:"foreignKey:CiscoMetadataID"`
	Asset         Assets          `gorm:"foreignKey:AssetID"`
	VLANPorts     []CiscoVLANPort `gorm:"foreignKey:CiscoInterfaceID;references:ID"`
}

func (CiscoInterface) TableName() string {
	return "cisco_interfaces"
}

// CiscoVLAN represents a Cisco VLAN in the database
type CiscoVLAN struct {
	ID              string    `gorm:"column:id;size:50;primaryKey"`
	CiscoMetadataID int64     `gorm:"column:cisco_metadata_id;not null;index"`
	AssetID         string    `gorm:"column:asset_id;not null;index"`
	VlanID          int       `gorm:"column:vlan_id;not null"` // VLAN number
	Name            string    `gorm:"column:name;size:100"`
	Status          string    `gorm:"column:status;size:50"` // active/suspend/act_unsup
	Type            string    `gorm:"column:type;size:50"`   // enet/tr/fddi/trcrf/fddinet/trnet
	Parent          int       `gorm:"column:parent"`         // Parent VLAN for private VLANs
	CreatedAt       time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	CiscoMetadata CiscoMetadata   `gorm:"foreignKey:CiscoMetadataID"`
	Asset         Assets          `gorm:"foreignKey:AssetID"`
	VLANPorts     []CiscoVLANPort `gorm:"foreignKey:CiscoVLANID;references:ID"`
}

func (CiscoVLAN) TableName() string {
	return "cisco_vlans"
}

// CiscoVLANPort represents individual port assignments to VLANs
type CiscoVLANPort struct {
	ID               string    `gorm:"column:id;size:50;primaryKey"`
	CiscoMetadataID  int64     `gorm:"column:cisco_metadata_id;not null;index"`
	AssetID          string    `gorm:"column:asset_id;not null;index"`
	CiscoVLANID      string    `gorm:"column:cisco_vlan_id;not null;index"`     // References CiscoVLAN.ID
	CiscoInterfaceID *string   `gorm:"column:cisco_interface_id;size:50;index"` // References CiscoInterface.ID
	VlanID           int       `gorm:"column:vlan_id;not null;index"`           // VLAN number for easy querying
	PortName         string    `gorm:"column:port_name;size:100;not null"`      // Port identifier (e.g., Fa0/1, Gi0/0/1)
	PortType         string    `gorm:"column:port_type;size:50"`                // access, trunk, etc.
	PortStatus       string    `gorm:"column:port_status;size:50"`              // active, inactive, etc.
	CreatedAt        time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	CiscoMetadata  CiscoMetadata   `gorm:"foreignKey:CiscoMetadataID"`
	Asset          Assets          `gorm:"foreignKey:AssetID"`
	CiscoVLAN      CiscoVLAN       `gorm:"foreignKey:CiscoVLANID;references:ID"`
	CiscoInterface *CiscoInterface `gorm:"foreignKey:CiscoInterfaceID;references:ID"`
}

func (CiscoVLANPort) TableName() string {
	return "cisco_vlan_ports"
}

// CiscoVRF represents a Cisco VRF (Virtual Routing and Forwarding) in the database
type CiscoVRF struct {
	ID                 string    `gorm:"column:id;size:50;primaryKey"`
	CiscoMetadataID    int64     `gorm:"column:cisco_metadata_id;not null;index"`
	AssetID            string    `gorm:"column:asset_id;not null;index"`
	Name               string    `gorm:"column:name;size:100;not null"`
	Description        string    `gorm:"column:description;size:500"`
	RouteTarget        string    `gorm:"column:route_target;size:100"`        // Route target for BGP
	RouteDistinguisher string    `gorm:"column:route_distinguisher;size:100"` // Route distinguisher
	Interfaces         string    `gorm:"column:interfaces;type:text"`         // JSON array of associated interfaces
	Status             string    `gorm:"column:status;size:50"`               // active/inactive
	CreatedAt          time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt          time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	CiscoMetadata CiscoMetadata `gorm:"foreignKey:CiscoMetadataID"`
	Asset         Assets        `gorm:"foreignKey:AssetID"`
}

func (CiscoVRF) TableName() string {
	return "cisco_vrfs"
}

// CiscoRoute represents a Cisco routing entry in the database
type CiscoRoute struct {
	ID              string    `gorm:"column:id;size:50;primaryKey"`
	CiscoMetadataID int64     `gorm:"column:cisco_metadata_id;not null;index"`
	AssetID         string    `gorm:"column:asset_id;not null;index"`
	VRFName         string    `gorm:"column:vrf_name;size:100"`        // VRF context
	Network         string    `gorm:"column:network;size:50;not null"` // Destination network
	Mask            string    `gorm:"column:mask;size:50;not null"`    // Subnet mask
	NextHop         string    `gorm:"column:next_hop;size:50"`         // Next hop IP
	Interface       string    `gorm:"column:interface;size:100"`       // Outgoing interface
	Metric          int       `gorm:"column:metric"`                   // Route metric
	AdminDistance   int       `gorm:"column:admin_distance"`           // Administrative distance
	Protocol        string    `gorm:"column:protocol;size:50"`         // connected/static/rip/ospf/eigrp/bgp
	Age             string    `gorm:"column:age;size:50"`              // Route age
	Tag             string    `gorm:"column:tag;size:50"`              // Route tag
	CreatedAt       time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	CiscoMetadata CiscoMetadata `gorm:"foreignKey:CiscoMetadataID"`
	Asset         Assets        `gorm:"foreignKey:AssetID"`
}

func (CiscoRoute) TableName() string {
	return "cisco_routes"
}

// CiscoNeighbor represents a Cisco CDP/LLDP neighbor in the database
type CiscoNeighbor struct {
	ID              string    `gorm:"column:id;size:50;primaryKey"`
	CiscoMetadataID int64     `gorm:"column:cisco_metadata_id;not null;index"`
	AssetID         string    `gorm:"column:asset_id;not null;index"`
	DeviceID        string    `gorm:"column:device_id;size:200;not null"`  // Remote device ID
	LocalPort       string    `gorm:"column:local_port;size:100;not null"` // Local interface
	RemotePort      string    `gorm:"column:remote_port;size:100"`         // Remote interface
	Platform        string    `gorm:"column:platform;size:200"`            // Device platform
	IPAddress       string    `gorm:"column:ip_address;size:45"`           // Neighbor IP
	Capabilities    string    `gorm:"column:capabilities;size:200"`        // Device capabilities
	Software        string    `gorm:"column:software;size:500"`            // Software version
	Duplex          string    `gorm:"column:duplex;size:20"`               // Duplex setting
	Protocol        string    `gorm:"column:protocol;size:20"`             // CDP/LLDP
	CreatedAt       time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	CiscoMetadata CiscoMetadata `gorm:"foreignKey:CiscoMetadataID"`
	Asset         Assets        `gorm:"foreignKey:AssetID"`
}

func (CiscoNeighbor) TableName() string {
	return "cisco_neighbors"
}

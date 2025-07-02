package mapper

import (
	"github.com/google/uuid"
	Domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	ScannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func AssetDomain2Storage(asset Domain.AssetDomain) (*types.Assets, []*types.AssetIPs) {
	// Convert risk int to string enum
	riskStr := "medium" // default
	switch asset.Risk {
	case 1:
		riskStr = "low"
	case 2:
		riskStr = "medium"
	case 3:
		riskStr = "high"
	case 4:
		riskStr = "critical"
	}

	// Convert asset value from int to float64
	assetValue := float64(asset.AssetValue)

	assetStorage := &types.Assets{
		ID:               asset.ID.String(),
		VendorID:         1, // Default to Fortinet, you may want to make this configurable
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Description:      asset.Description,
		AssetType:        asset.Type, // Changed from Type to AssetType
		Risk:             riskStr,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        asset.UpdatedAt,
	}

	// Create AssetIP objects for each IP
	assetIPs := make([]*types.AssetIPs, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		mac := ip.MACAddress
		if mac == "" {
			mac = "" // Leave empty if not provided
		}

		assetIPID := uuid.New().String()
		assetIPs = append(assetIPs, &types.AssetIPs{
			ID:         assetIPID,
			AssetID:    asset.ID.String(),
			IPAddress:  ip.IP,
			MacAddress: mac,
			CreatedAt:  asset.CreatedAt,
		})
	}

	return assetStorage, assetIPs
}

func AssetStorage2Domain(asset types.Assets) (*Domain.AssetDomain, error) {
	uid, err := Domain.AssetUUIDFromString(asset.ID)
	if err != nil {
		return nil, err
	}

	ports := make([]Domain.Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		var serviceName, serviceVersion, description string
		if port.ServiceName != nil {
			serviceName = *port.ServiceName
		}
		if port.ServiceVersion != nil {
			serviceVersion = *port.ServiceVersion
		}
		if port.Description != nil {
			description = *port.Description
		}

		ports = append(ports, Domain.Port{
			ID:             port.ID,
			AssetID:        port.AssetID,
			PortNumber:     port.PortNumber,
			Protocol:       port.Protocol,
			State:          port.State,
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
			Description:    description,
			DiscoveredAt:   port.DiscoveredAt,
		})
	}

	vms := make([]Domain.VMwareVM, 0, len(asset.VMwareVMs))
	for _, vm := range asset.VMwareVMs {
		vms = append(vms, Domain.VMwareVM{
			VMID:         vm.VMID,
			AssetID:      vm.AssetID,
			VMName:       vm.VMName,
			Hypervisor:   vm.Hypervisor,
			CPUCount:     int32(vm.CPUCount),
			MemoryMB:     int32(vm.MemoryMB),
			DiskSizeGB:   vm.DiskSizeGB,
			PowerState:   vm.PowerState,
			LastSyncedAt: vm.LastSyncedAt,
		})
	}

	ips := make([]Domain.AssetIP, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		ips = append(ips, Domain.AssetIP{
			AssetID:    ip.AssetID,
			IP:         ip.IPAddress,
			MACAddress: ip.MacAddress,
		})
	}

	// Convert risk string enum back to int
	risk := 2 // default medium
	switch asset.Risk {
	case "low":
		risk = 1
	case "medium":
		risk = 2
	case "high":
		risk = 3
	case "critical":
		risk = 4
	}

	// Convert asset value from float64 to int
	assetValue := int(asset.AssetValue)

	// Handle deleted_at for domain model
	updatedAt := asset.UpdatedAt
	if asset.DeletedAt != nil {
		// If deleted, use deletion time as updated time
		updatedAt = *asset.DeletedAt
	}

	return &Domain.AssetDomain{
		ID:               uid,
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Type:             asset.AssetType, // Changed from Type to AssetType
		Description:      asset.Description,
		Risk:             risk,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        updatedAt,
		Ports:            ports,
		VMwareVMs:        vms,
		AssetIPs:         ips,
	}, nil
}

func AssetStorage2DomainWithScannerType(asset types.Assets, scannerType string) (*Domain.AssetDomain, error) {
	assetDomain, err := AssetStorage2Domain(asset)
	if err != nil {
		return nil, err
	}

	scannerObj := &ScannerDomain.ScannerDomain{
		Type: scannerType,
	}

	assetDomain.Scanner = scannerObj
	return assetDomain, nil
}

// PortDomain2Storage maps domain.Port to storage.Port
func PortDomain2Storage(port Domain.Port) *types.Port {
	portStorage := &types.Port{
		ID:           port.ID,
		AssetID:      port.AssetID,
		PortNumber:   port.PortNumber,
		Protocol:     port.Protocol,
		State:        port.State,
		DiscoveredAt: port.DiscoveredAt,
	}

	// Only set pointer fields if they have values
	if port.ServiceName != "" {
		portStorage.ServiceName = &port.ServiceName
	}
	if port.ServiceVersion != "" {
		portStorage.ServiceVersion = &port.ServiceVersion
	}
	if port.Description != "" {
		portStorage.Description = &port.Description
	}

	return portStorage
}

// AssetIPDomain2Storage maps domain.AssetIP to storage.AssetIP
func AssetIPDomain2Storage(ip Domain.AssetIP) *types.AssetIPs {
	ipID := uuid.New().String()

	return &types.AssetIPs{
		ID:         ipID,
		AssetID:    ip.AssetID,
		IPAddress:  ip.IP,
		MacAddress: ip.MACAddress,
	}
}

package storage

import (
	"context"
	"time"

	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/gorm"
)

type CiscoRepo struct {
	db *gorm.DB
}

func NewCiscoRepo(db *gorm.DB) *CiscoRepo {
	return &CiscoRepo{
		db: db,
	}
}

// ============================================================================
// METADATA OPERATIONS
// ============================================================================

func (r *CiscoRepo) GetCiscoMetadataIDByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) (int64, error) {
	var ciscoMetadata types.CiscoMetadata
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		First(&ciscoMetadata).Error
	if err != nil {
		return 0, err
	}
	return ciscoMetadata.ID, nil
}

func (r *CiscoRepo) GetCiscoMetadataIDByScannerID(ctx context.Context, scannerID int64) (int64, error) {
	var ciscoMetadata types.CiscoMetadata
	err := r.db.WithContext(ctx).
		Where("scanner_id = ?", scannerID).
		First(&ciscoMetadata).Error
	if err != nil {
		return 0, err
	}
	return ciscoMetadata.ID, nil
}

// ============================================================================
// UNIFIED INTERFACES OPERATIONS (was CiscoInterfaces)
// ============================================================================

func (r *CiscoRepo) MarkExistingCiscoInterfacesDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("interfaces").
		Where("asset_id = ? AND cisco_metadata_id = ? AND scanner_type = 'cisco'", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoInterfaces(ctx context.Context, interfaces []types.Interfaces) error {
	if len(interfaces) == 0 {
		return nil
	}

	// Use transaction for batch insert
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, iface := range interfaces {
			// Ensure this is marked as a Cisco interface
			iface.ScannerType = "cisco"

			if err := tx.Table("interfaces").Create(&iface).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoInterfacesByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.Interfaces, error) {
	var interfaces []types.Interfaces
	err := r.db.WithContext(ctx).
		Table("interfaces").
		Where("asset_id = ? AND scanner_type = 'cisco'", assetID.String()).
		Find(&interfaces).Error
	return interfaces, err
}

// ============================================================================
// UNIFIED VLANS OPERATIONS (was CiscoVLANs)
// ============================================================================

func (r *CiscoRepo) MarkExistingCiscoVLANsDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("vlans").
		Where("cisco_metadata_id = ? AND scanner_type = 'cisco'", ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoVLANs(ctx context.Context, vlans []types.VLANs) error {
	if len(vlans) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, vlan := range vlans {
			// Ensure this is marked as a Cisco VLAN
			vlan.ScannerType = "cisco"

			if err := tx.Table("vlans").Create(&vlan).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoVLANsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.VLANs, error) {
	var vlans []types.VLANs
	err := r.db.WithContext(ctx).
		Table("vlans").
		Joins("JOIN interfaces ON vlans.parent_interface_id = interfaces.id").
		Where("interfaces.asset_id = ? AND vlans.scanner_type = 'cisco'", assetID.String()).
		Find(&vlans).Error
	return vlans, err
}

// ============================================================================
// CISCO VRFs OPERATIONS
// ============================================================================

func (r *CiscoRepo) MarkExistingCiscoVRFsDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("cisco_vrfs").
		Where("asset_id = ? AND cisco_metadata_id = ?", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoVRFs(ctx context.Context, vrfs []types.CiscoVRF) error {
	if len(vrfs) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, vrf := range vrfs {
			if err := tx.Create(&vrf).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoVRFsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.CiscoVRF, error) {
	var vrfs []types.CiscoVRF
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		Find(&vrfs).Error
	return vrfs, err
}

// ============================================================================
// CISCO ROUTES OPERATIONS
// ============================================================================

func (r *CiscoRepo) MarkExistingCiscoRoutesDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("cisco_routes").
		Where("asset_id = ? AND cisco_metadata_id = ?", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoRoutes(ctx context.Context, routes []types.CiscoRoute) error {
	if len(routes) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, route := range routes {
			if err := tx.Create(&route).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoRoutesByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.CiscoRoute, error) {
	var routes []types.CiscoRoute
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		Find(&routes).Error
	return routes, err
}

// ============================================================================
// CISCO NEIGHBORS OPERATIONS
// ============================================================================

func (r *CiscoRepo) MarkExistingCiscoNeighborsDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("cisco_neighbors").
		Where("asset_id = ? AND cisco_metadata_id = ?", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoNeighbors(ctx context.Context, neighbors []types.CiscoNeighbor) error {
	if len(neighbors) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, neighbor := range neighbors {
			if err := tx.Create(&neighbor).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoNeighborsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.CiscoNeighbor, error) {
	var neighbors []types.CiscoNeighbor
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		Find(&neighbors).Error
	return neighbors, err
}

// ============================================================================
// CLEANUP OPERATIONS
// ============================================================================

func (r *CiscoRepo) DeleteCiscoDataByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error

		// Delete Cisco interfaces from unified interfaces table
		err = tx.Table("interfaces").
			Where("asset_id = ? AND scanner_type = 'cisco'", assetID.String()).
			Delete(&types.Interfaces{}).Error
		if err != nil {
			return err
		}

		// Delete Cisco VLANs from unified VLANs table
		err = tx.Table("vlans").
			Joins("JOIN interfaces ON vlans.parent_interface_id = interfaces.id").
			Where("interfaces.asset_id = ? AND vlans.scanner_type = 'cisco'", assetID.String()).
			Delete(&types.VLANs{}).Error
		if err != nil {
			return err
		}

		// Delete VRFs
		err = tx.Where("asset_id = ?", assetID.String()).Delete(&types.CiscoVRF{}).Error
		if err != nil {
			return err
		}

		// Delete routes
		err = tx.Where("asset_id = ?", assetID.String()).Delete(&types.CiscoRoute{}).Error
		if err != nil {
			return err
		}

		// Delete neighbors
		err = tx.Where("asset_id = ?", assetID.String()).Delete(&types.CiscoNeighbor{}).Error
		if err != nil {
			return err
		}

		return nil
	})
}

// ============================================================================
// VLAN PORT OPERATIONS (now part of interfaces table)
// ============================================================================

// Note: VLAN port functionality is now integrated into the interfaces table
// The PortType and PortStatus fields in the interfaces table handle this

func (r *CiscoRepo) MarkExistingCiscoVLANPortsDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	// This now marks interfaces that represent VLAN ports
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("interfaces").
		Where("asset_id = ? AND cisco_metadata_id = ? AND scanner_type = 'cisco' AND port_type IS NOT NULL",
			assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoVLANPorts(ctx context.Context, vlanPorts []types.Interfaces) error {
	if len(vlanPorts) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, vlanPort := range vlanPorts {
			// Ensure this is marked as a Cisco interface with VLAN port data
			vlanPort.ScannerType = "cisco"

			if err := tx.Table("interfaces").Create(&vlanPort).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoVLANPortsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.Interfaces, error) {
	var vlanPorts []types.Interfaces
	err := r.db.WithContext(ctx).
		Table("interfaces").
		Where("asset_id = ? AND scanner_type = 'cisco' AND port_type IS NOT NULL", assetID.String()).
		Find(&vlanPorts).Error
	return vlanPorts, err
}

func (r *CiscoRepo) GetCiscoVLANPortsByVLANID(ctx context.Context, assetID assetDomain.AssetUUID, vlanID int) ([]types.Interfaces, error) {
	var vlanPorts []types.Interfaces
	err := r.db.WithContext(ctx).
		Table("interfaces").
		Where("asset_id = ? AND scanner_type = 'cisco' AND vlan_id = ?", assetID.String(), vlanID).
		Find(&vlanPorts).Error
	return vlanPorts, err
}

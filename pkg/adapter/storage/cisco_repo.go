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

// GetCiscoMetadataIDByAssetID retrieves the Cisco metadata ID for a given asset
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

// GetCiscoMetadataIDByScannerID retrieves the Cisco metadata ID for a given scanner
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

// Cisco Interfaces
func (r *CiscoRepo) MarkExistingCiscoInterfacesDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("cisco_interfaces").
		Where("asset_id = ? AND cisco_metadata_id = ?", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
	// Note: If you want soft deletes, add a deleted_at column and update that instead
}

func (r *CiscoRepo) StoreCiscoInterfaces(ctx context.Context, interfaces []types.CiscoInterface) error {
	if len(interfaces) == 0 {
		return nil
	}

	// Use transaction for batch insert
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, iface := range interfaces {
			if err := tx.Create(&iface).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoInterfacesByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.CiscoInterface, error) {
	var interfaces []types.CiscoInterface
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		Find(&interfaces).Error
	return interfaces, err
}

// Cisco VLANs
func (r *CiscoRepo) MarkExistingCiscoVLANsDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("cisco_vlans").
		Where("asset_id = ? AND cisco_metadata_id = ?", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoVLANs(ctx context.Context, vlans []types.CiscoVLAN) error {
	if len(vlans) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, vlan := range vlans {
			if err := tx.Create(&vlan).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoVLANsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.CiscoVLAN, error) {
	var vlans []types.CiscoVLAN
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		Find(&vlans).Error
	return vlans, err
}

// Cisco VRFs
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

// Cisco Routes
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

// Cisco Neighbors
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

// Cleanup methods for removing old data
func (r *CiscoRepo) DeleteCiscoDataByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete all Cisco-related data for this asset
		var err error

		// Delete interfaces
		err = tx.Where("asset_id = ?", assetID.String()).Delete(&types.CiscoInterface{}).Error
		if err != nil {
			return err
		}

		// Delete VLANs
		err = tx.Where("asset_id = ?", assetID.String()).Delete(&types.CiscoVLAN{}).Error
		if err != nil {
			return err
		}

		// Delete VLAN ports
		err = tx.Where("asset_id = ?", assetID.String()).Delete(&types.CiscoVLANPort{}).Error
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

// Cisco VLAN Ports
func (r *CiscoRepo) MarkExistingCiscoVLANPortsDeleted(ctx context.Context, assetID assetDomain.AssetUUID, ciscoMetadataID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Table("cisco_vlan_ports").
		Where("asset_id = ? AND cisco_metadata_id = ?", assetID.String(), ciscoMetadataID).
		Update("updated_at", now).Error
}

func (r *CiscoRepo) StoreCiscoVLANPorts(ctx context.Context, vlanPorts []types.CiscoVLANPort) error {
	if len(vlanPorts) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, vlanPort := range vlanPorts {
			if err := tx.Create(&vlanPort).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CiscoRepo) GetCiscoVLANPortsByAssetID(ctx context.Context, assetID assetDomain.AssetUUID) ([]types.CiscoVLANPort, error) {
	var vlanPorts []types.CiscoVLANPort
	err := r.db.WithContext(ctx).
		Where("asset_id = ?", assetID.String()).
		Find(&vlanPorts).Error
	return vlanPorts, err
}

func (r *CiscoRepo) GetCiscoVLANPortsByVLANID(ctx context.Context, assetID assetDomain.AssetUUID, vlanID int) ([]types.CiscoVLANPort, error) {
	var vlanPorts []types.CiscoVLANPort
	err := r.db.WithContext(ctx).
		Where("asset_id = ? AND vlan_id = ?", assetID.String(), vlanID).
		Find(&vlanPorts).Error
	return vlanPorts, err
}

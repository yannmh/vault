package vault

import (
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// NewIdentityStore creates a new identity store
func NewIdentityStore(core *Core, config *logical.BackendConfig) (*identityStore, error) {
	var err error

	// Create a new in-memory database for the identity store
	db, err := memdb.NewMemDB(identityStoreSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to create memdb for identity store: %v", err)
	}

	iStore := &identityStore{
		view:                  config.StorageView,
		db:                    db,
		entityLocks:           locksutil.CreateLocks(),
		logger:                core.logger,
		validateMountPathFunc: core.router.validateMount,
	}

	packerConfig := &storagePackerConfig{
		ViewPrefix: "entities/",
	}

	iStore.storagePacker, err = NewStoragePacker(iStore.view, packerConfig, iStore.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage buckets for identity store: %v", err)
	}

	iStore.Backend = &framework.Backend{
		Paths: framework.PathAppend(
			entityPaths(iStore),
			identityPaths(iStore),
		),
	}

	// Not setting iStore.Invalidate here because there is no storage path
	// at the moment which affects the state of identity store.

	_, err = iStore.Setup(config)
	if err != nil {
		return nil, err
	}

	return iStore, nil
}

// EntityByIdentityFactors fetches the entity based on factors of identity, i.e mount
// ID and the identity name.
func (i *identityStore) EntityByIdentityFactors(mountID, identityName string) (*entityStorageEntry, error) {
	if mountID == "" {
		return nil, fmt.Errorf("missing mount id")
	}

	if identityName == "" {
		return nil, fmt.Errorf("missing identity name")
	}

	identity, err := i.memDBIdentityByFactors(mountID, identityName)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	return i.memDBEntityByIdentityID(identity.ID)
}

// CreateEntity creates a new entity. This is used by core to
// associate each login attempt by an identity to a unified entity in Vault.
// This method should be called *after* ensuring that the identity is not
// already tied to an entity.
func (i *identityStore) CreateEntity(identity *logical.Identity) (*entityStorageEntry, error) {
	var err error

	if identity == nil {
		return nil, fmt.Errorf("identity is nil")
	}

	entity := &entityStorageEntry{}

	err = sanitizeEntity(entity)
	if err != nil {
		return nil, err
	}

	// Create a new identity
	newIdentity := &identityIndexEntry{
		EntityID:  entity.ID,
		Name:      identity.Name,
		MountType: identity.MountType,
		MountID:   identity.MountID,
	}

	err = i.sanitizeIdentity(newIdentity)
	if err != nil {
		return nil, err
	}

	// Append the new identity to the new entity
	entity.Identities = []*identityIndexEntry{
		newIdentity,
	}

	// Update MemDB and persist entity object
	err = i.upsertEntity(entity, nil, true)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

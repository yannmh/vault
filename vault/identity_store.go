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
			personaPaths(iStore),
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

// EntityByPersonaFactors fetches the entity based on factors of persona, i.e mount
// ID and the persona name.
func (i *identityStore) EntityByPersonaFactors(mountID, personaName string) (*entityStorageEntry, error) {
	if mountID == "" {
		return nil, fmt.Errorf("missing mount id")
	}

	if personaName == "" {
		return nil, fmt.Errorf("missing persona name")
	}

	persona, err := i.memDBPersonaByFactors(mountID, personaName)
	if err != nil {
		return nil, err
	}

	if persona == nil {
		return nil, nil
	}

	return i.memDBEntityByPersonaID(persona.ID)
}

// CreateEntity creates a new entity. This is used by core to
// associate each login attempt by a persona to a unified entity in Vault.
// This method should be called *after* ensuring that the persona is not
// already tied to an entity.
func (i *identityStore) CreateEntity(persona *logical.Persona) (*entityStorageEntry, error) {
	var err error

	if persona == nil {
		return nil, fmt.Errorf("persona is nil")
	}

	entity := &entityStorageEntry{}

	err = sanitizeEntity(entity)
	if err != nil {
		return nil, err
	}

	// Create a new persona
	newPersona := &personaIndexEntry{
		EntityID:  entity.ID,
		Name:      persona.Name,
		MountType: persona.MountType,
		MountID:   persona.MountID,
	}

	err = i.sanitizePersona(newPersona)
	if err != nil {
		return nil, err
	}

	// Append the new persona to the new entity
	entity.Personae = []*personaIndexEntry{
		newPersona,
	}

	// Update MemDB and persist entity object
	err = i.upsertEntity(entity, nil, true)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

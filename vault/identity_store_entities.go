package vault

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// entityPaths returns the API endpoints supported to operate on entities.
// Following are the paths supported:
// entity - To register a new entity
// entity/id - To lookup, modify, delete and list entities based on ID
// entity/merge/id - To merge entities based on ID
func entityPaths(i *identityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "entity",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the entity",
				},
				"metadata": {
					Type:        framework.TypeStringSlice,
					Description: "Metadata to be associated with the entity. Format should be a comma separated list of `key=value` pairs.",
				},
				"policies": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Policies to be tied to the entity",
				},
				// "identities", extracted from raw field data
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathEntityRegister,
			},

			HelpSynopsis:    strings.TrimSpace(entityHelp["entity"][0]),
			HelpDescription: strings.TrimSpace(entityHelp["entity"][1]),
		},
		{
			Pattern: "entity/id/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the entity",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the entity",
				},
				"metadata": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Metadata to be associated with the entity. Format should be a comma separated list of `key=value` pairs.",
				},
				"policies": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Policies to be tied to the entity",
				},
				// "identities", extracted from raw field data
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathEntityIDUpdate,
				logical.ReadOperation:   i.pathEntityIDRead,
				logical.DeleteOperation: i.pathEntityIDDelete,
			},

			HelpSynopsis:    strings.TrimSpace(entityHelp["entity-id"][0]),
			HelpDescription: strings.TrimSpace(entityHelp["entity-id"][1]),
		},
		{
			Pattern: "entity/id/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: i.pathEntityIDList,
			},

			HelpSynopsis:    strings.TrimSpace(entityHelp["entity-id-list"][0]),
			HelpDescription: strings.TrimSpace(entityHelp["entity-id-list"][1]),
		},
		{
			Pattern: "entity/merge/id/?$",
			Fields: map[string]*framework.FieldSchema{
				"from_entity_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Entity IDs which needs to get merged",
				},
				"to_entity_id": {
					Type:        framework.TypeString,
					Description: "Entity ID into which all the other entities needs to get merged",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathEntityMergeID,
			},

			HelpSynopsis:    strings.TrimSpace(entityHelp["entity-merge-id"][0]),
			HelpDescription: strings.TrimSpace(entityHelp["entity-merge-id"][1]),
		},
	}
}

// pathEntityMergeID merges two or more entities into a single entity
func (i *identityStore) pathEntityMergeID(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	toEntityID := d.Get("to_entity_id").(string)
	if toEntityID == "" {
		return logical.ErrorResponse("missing entity id to merge to"), nil
	}

	fromEntityIDs := d.Get("from_entity_ids").([]string)
	if len(fromEntityIDs) == 0 {
		return logical.ErrorResponse("missing entity ids to merge from"), nil
	}

	toEntityForLocking, err := i.memDBEntityByID(toEntityID)
	if err != nil {
		return nil, err
	}

	if toEntityForLocking == nil {
		return logical.ErrorResponse("entity id to merge to is invalid"), nil
	}

	// Acquire the lock to modify the entity storage entry to merge to
	toEntityLock := locksutil.LockForKey(i.entityLocks, toEntityForLocking.ID)
	toEntityLock.Lock()
	defer toEntityLock.Unlock()

	// Create a MemDB transaction to merge entities
	txn := i.db.Txn(true)
	defer txn.Abort()

	// Re-read post lock acquisition
	toEntity, err := i.memDBEntityByID(toEntityID)
	if err != nil {
		return nil, err
	}

	if toEntity == nil {
		return logical.ErrorResponse("entity id to merge to is invalid"), nil
	}

	if toEntity.ID != toEntityForLocking.ID {
		return logical.ErrorResponse("acquired lock for an undesired entity"), nil
	}

	for _, fromEntityID := range fromEntityIDs {
		if fromEntityID == toEntityID {
			return logical.ErrorResponse("to_entity_id should not be present in from_entity_ids"), nil
		}

		lockFromEntity, err := i.memDBEntityByID(fromEntityID)
		if err != nil {
			return nil, err
		}

		if lockFromEntity == nil {
			return logical.ErrorResponse("entity id to merge from is invalid"), nil
		}

		// Acquire the lock to modify the entity storage entry to merge from
		fromEntityLock := locksutil.LockForKey(i.entityLocks, lockFromEntity.ID)

		// There are only 256 lock buckets and the chances of entity ID collision
		// is fairly high. When we are merging entities belonging to the same
		// bucket, multiple attempts to acquire the same lock should be avoided.
		if fromEntityLock != toEntityLock {
			fromEntityLock.Lock()
			defer fromEntityLock.Unlock()
		}

		// Re-read the entities post lock acquisition
		fromEntity, err := i.memDBEntityByID(fromEntityID)
		if err != nil {
			return nil, err
		}

		if fromEntity == nil {
			return logical.ErrorResponse("entity id to merge from is invalid"), nil
		}

		if fromEntity.ID != lockFromEntity.ID {
			return logical.ErrorResponse("acquired lock for an undesired entity"), nil
		}

		for _, identity := range fromEntity.Identities {
			// Special case the identities that gets transfered over due to merge
			// operation. This might also aid in controlling any actions to be
			// taken on the merged identities.
			identity.MountType = "EntityAlias"

			// Set the desired entity id
			identity.EntityID = toEntity.ID

			// Set the entity id of which this identity is now an alias to
			identity.MergedFrom = fromEntity.ID

			err = i.memDBUpsertIdentityInTxn(txn, identity)
			if err != nil {
				return nil, fmt.Errorf("failed to update identity during merge: %v", err)
			}

			// Add the identity to the desired entity
			toEntity.Identities = append(toEntity.Identities, identity)
		}

		// Add the entity from which we are merging from to the list of entities
		// the entity we are merging into is composed of
		toEntity.MergedEntities = append(toEntity.MergedEntities, fromEntity.ID)

		// Delete the entity which we are merging from in MemDB using the same transaction
		err = i.memDBDeleteEntityInTxn(txn, fromEntity)
		if err != nil {
			return nil, err
		}

		// Delete the entity which we are merging from in storage
		err = i.storagePacker.DeleteItem(fromEntity.ID)
		if err != nil {
			return nil, err
		}
	}

	// Persist the entity which we are merging to
	err = i.storagePacker.PutItem(toEntity)
	if err != nil {
		return nil, err
	}

	// Committing the transaction *after* successfully performing storage
	// persistence
	txn.Commit()

	return nil, nil
}

// pathEntityRegister is used to register a new entity
func (i *identityStore) pathEntityRegister(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleEntityUpdateCommon(req, d, nil)
}

// pathEntityIDUpdate is used to update an entity based on the given entity ID
func (i *identityStore) pathEntityIDUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get entity id
	entityID := d.Get("id").(string)

	if entityID == "" {
		return logical.ErrorResponse("missing entity id"), nil
	}

	entity, err := i.memDBEntityByID(entityID)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, fmt.Errorf("invalid entity id")
	}

	return i.handleEntityUpdateCommon(req, d, entity)
}

// handleEntityUpdateCommon is used to update an entity
func (i *identityStore) handleEntityUpdateCommon(req *logical.Request, d *framework.FieldData, entity *entityStorageEntry) (*logical.Response, error) {
	var err error
	var newEntity bool

	// Entity will be nil when a new entity is being registered; create a new
	// struct in that case.
	if entity == nil {
		entity = &entityStorageEntry{}
		newEntity = true
	}

	// Update the policies
	entity.Policies = d.Get("policies").([]string)

	// Get the name
	entityName := d.Get("name").(string)
	if entityName != "" {
		entityByName, err := i.memDBEntityByName(entityName)
		if err != nil {
			return nil, err
		}
		switch {
		case (newEntity && entityByName != nil), (entityByName != nil && entity.ID != "" && entityByName.ID != entity.ID):
			return logical.ErrorResponse("entity name is already in use"), nil
		}
		entity.Name = entityName
	}

	// Get entity metadata

	// Accept metadata in the form of map[string]string to be able to index on
	// it
	entityMetadataRaw, ok := d.GetOk("metadata")
	if ok {
		entity.Metadata, err = i.parseMetadata(entityMetadataRaw.([]string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("failed to parse entity metadata: %v", err)), nil
		}
	}

	// ID creation and some validations
	err = sanitizeEntity(entity)
	if err != nil {
		return nil, err
	}

	// Get the identities input
	var identitiesSlice []interface{}
	identitiesRaw, ok := d.Raw["identities"]
	if ok {
		identitiesSlice = identitiesRaw.([]interface{})
	}

	// Prepare parsed collection of given identities
	var identities []*identityIndexEntry
	for _, identityRaw := range identitiesSlice {
		var input identityInput
		if err = mapstructure.WeakDecode(identityRaw, &input); err != nil {
			return nil, fmt.Errorf("failed to decode identity input: %v", err)
		}

		if input.MountPath == "" {
			return logical.ErrorResponse("missing mount path"), nil
		}

		mountValidationResp := i.validateMountPathFunc(input.MountPath)
		if mountValidationResp == nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid mount path %q", input.MountPath)), nil
		}

		identityMetadata, err := i.parseMetadata(input.Metadata)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("failed to parse identity metadata: %v", err)), nil
		}

		identity := &identityIndexEntry{
			EntityID:  entity.ID,
			Name:      input.Name,
			Metadata:  identityMetadata,
			MountID:   mountValidationResp.MountID,
			MountType: mountValidationResp.MountType,
		}

		err = i.sanitizeIdentity(identity)
		if err != nil {
			return nil, err
		}

		identities = append(identities, identity)
	}

	entity.Identities = identities

	// Prepare the response
	respData := map[string]interface{}{
		"id": entity.ID,
	}

	var identityIDs []string
	for _, identity := range entity.Identities {
		identityIDs = append(identityIDs, identity.ID)
	}

	respData["identities"] = identityIDs

	// Update MemDB and persist entity object
	err = i.upsertEntity(entity, nil, true)
	if err != nil {
		return nil, err
	}

	// Return ID of the entity that was either created or updated along with
	// its identities
	return &logical.Response{
		Data: respData,
	}, nil
}

// pathEntityIDRead returns the properties of an entity for a given entity ID
func (i *identityStore) pathEntityIDRead(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entityID := d.Get("id").(string)
	if entityID == "" {
		return logical.ErrorResponse("missing entity id"), nil
	}

	entity, err := i.memDBEntityByID(entityID)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, nil
	}

	// Be sure that MountID is not returned here. Currently the structs tag
	// ignores the field while creating map. This behaviour should be retained
	// if the code here changes.
	resp := &logical.Response{
		Data: structs.New(entity).Map(),
	}

	return resp, nil
}

// pathEntityIDDelete deletes the entity for a given entity ID
func (i *identityStore) pathEntityIDDelete(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entityID := d.Get("id").(string)
	if entityID == "" {
		return logical.ErrorResponse("missing entity id"), nil
	}

	return nil, i.deleteEntity(entityID)
}

// pathEntityIDList lists the IDs of all the valid entities in the identity
// store
func (i *identityStore) pathEntityIDList(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ws := memdb.NewWatchSet()
	iter, err := i.memDBEntities(ws)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch iterator for entities in memdb: %v", err)
	}

	var entityIDs []string
	for {
		raw := iter.Next()
		if raw == nil {
			break
		}
		entityIDs = append(entityIDs, raw.(*entityStorageEntry).ID)
	}

	return logical.ListResponse(entityIDs), nil
}

var entityHelp = map[string][2]string{
	"entity": {
		"Create a new entity",
		"",
	},
	"entity-id": {
		"Update, read or delete an entity using entity ID",
		"",
	},
	"entity-id-list": {
		"List all the entity IDs",
		"",
	},
	"entity-merge-id": {
		"Merge two or more entities together",
		"",
	},
}

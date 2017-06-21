package vault

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// identityPaths returns the API endpoints to operate on identities.
// Following are the paths supported:
// identity - To register/modify an identity
// identity/id - To lookup, delete and list identities based on ID
func identityPaths(i *identityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "identity",
			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Entity ID to which this identity belongs to",
				},
				"mount_path": {
					Type:        framework.TypeString,
					Description: "Mount path to which this identity belongs to",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the identity",
				},
				"metadata": {
					Type:        framework.TypeStringSlice,
					Description: "Metadata to be associated with the identity. Format should be a comma separated list of `key=value` pairs.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathIdentityRegister,
			},

			HelpSynopsis:    strings.TrimSpace(identityHelp["identity"][0]),
			HelpDescription: strings.TrimSpace(identityHelp["identity"][1]),
		},
		{
			Pattern: "identity/id/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the identity",
				},
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Entity ID to which this identity should be tied to",
				},
				"mount_path": {
					Type:        framework.TypeString,
					Description: "Mount path to which this identity belongs to",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the identity",
				},
				"metadata": {
					Type:        framework.TypeStringSlice,
					Description: "Metadata to be associated with the identity. Format should be a comma separated list of `key=value` pairs.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathIdentityIDUpdate,
				logical.ReadOperation:   i.pathIdentityIDRead,
				logical.DeleteOperation: i.pathIdentityIDDelete,
			},

			HelpSynopsis:    strings.TrimSpace(identityHelp["identity-id"][0]),
			HelpDescription: strings.TrimSpace(identityHelp["identity-id"][1]),
		},
		{
			Pattern: "identity/id/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: i.pathIdentityIDList,
			},

			HelpSynopsis:    strings.TrimSpace(identityHelp["identity-id-list"][0]),
			HelpDescription: strings.TrimSpace(identityHelp["identity-id-list"][1]),
		},
	}
}

// pathIdentityRegister is used to register new identity
func (i *identityStore) pathIdentityRegister(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleIdentityUpdateCommon(req, d, nil)
}

// pathIdentityIDUpdate is used to update an identity based on the given
// identity ID
func (i *identityStore) pathIdentityIDUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get identity id
	identityID := d.Get("id").(string)

	if identityID == "" {
		return logical.ErrorResponse("missing identity id"), nil
	}

	identity, err := i.memDBIdentityByID(identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return logical.ErrorResponse("invalid identity id"), nil
	}

	return i.handleIdentityUpdateCommon(req, d, identity)
}

// handleIdentityUpdateCommon is used to update an identity
func (i *identityStore) handleIdentityUpdateCommon(req *logical.Request, d *framework.FieldData, identity *identityIndexEntry) (*logical.Response, error) {
	var err error
	var newIdentity bool
	var entity *entityStorageEntry
	var previousEntity *entityStorageEntry

	// Identity will be nil when a new identity is being registered; create a
	// new struct in that case.
	if identity == nil {
		identity = &identityIndexEntry{}
		newIdentity = true
	}

	// Get entity id
	entityID := d.Get("entity_id").(string)
	if entityID != "" {
		entity, err := i.memDBEntityByID(entityID)
		if err != nil {
			return nil, err
		}
		if entity == nil {
			return logical.ErrorResponse("invalid entity id"), nil
		}
	}

	// Get identity name
	identityName := d.Get("name").(string)
	if identityName == "" {
		return logical.ErrorResponse("missing identity name"), nil
	}

	// Get mount path to which the identity belongs to
	mountPath := d.Get("mount_path").(string)
	if mountPath == "" {
		return logical.ErrorResponse("missing mount path"), nil
	}

	// Get identity metadata

	// Accept metadata in the form of map[string]string to be able to index on
	// it
	var identityMetadata map[string]string
	identityMetadataRaw, ok := d.GetOk("metadata")
	if ok {
		identityMetadata, err = i.parseMetadata(identityMetadataRaw.([]string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("failed to parse identity metadata: %v", err)), nil
		}
	}

	mountValidationResp := i.validateMountPathFunc(mountPath)
	if mountValidationResp == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid mount path %q", mountPath)), nil
	}

	identityByFactors, err := i.memDBIdentityByFactors(mountValidationResp.MountID, identityName)
	if err != nil {
		return nil, err
	}

	if newIdentity {
		if identityByFactors != nil {
			return logical.ErrorResponse("combination of mount path and identity name is already in use"), nil
		}

		// If this is an identity being tied to a non-existent entity, create
		// a new entity for it.
		if entity == nil {
			entity = &entityStorageEntry{
				Identities: []*identityIndexEntry{
					identity,
				},
			}
		} else {
			entity.Identities = append(entity.Identities, identity)
		}
	} else {
		// Verify that the combination of identity name and mount path is not
		// already tied to a different identity
		if identityByFactors != nil && identityByFactors.ID != identity.ID {
			return logical.ErrorResponse("combination of mount path and identity name is already in use"), nil
		}

		// Fetch the entity to which the identity is tied to
		existingEntity, err := i.memDBEntityByIdentityID(identity.ID)
		if err != nil {
			return nil, err
		}

		if existingEntity == nil {
			return nil, fmt.Errorf("identity is not associated with an entity")
		}

		if entity != nil && entity.ID != existingEntity.ID {
			// Identity should be transferred from 'existingEntity' to 'entity'
			i.deleteIdentityFromEntity(existingEntity, identity)
			previousEntity = existingEntity
			entity.Identities = append(entity.Identities, identity)
		} else {
			// Update entity with modified identity
			err = i.updateIdentityInEntity(existingEntity, identity)
			if err != nil {
				return nil, err
			}
			entity = existingEntity
		}
	}

	// ID creation and other validations; This is more useful for new entities
	// and may not perform anything for the existing entities. Placing the
	// check here to make the flow common for both new and existing entities.
	err = sanitizeEntity(entity)
	if err != nil {
		return nil, err
	}

	// Update the fields
	identity.Name = identityName
	identity.Metadata = identityMetadata
	identity.MountID = mountValidationResp.MountID
	identity.MountType = mountValidationResp.MountType

	// Set the entity ID in the identity index. This should be done after
	// sanitizing entity.
	identity.EntityID = entity.ID

	// ID creation and other validations
	err = i.sanitizeIdentity(identity)
	if err != nil {
		return nil, err
	}

	// Index entity and its identities in MemDB and persist entity along with
	// identities in storage. If the identity is being transferred over from
	// one entity to another, previous entity needs to get refreshed in MemDB
	// and persisted in storage as well.
	err = i.upsertEntity(entity, previousEntity, true)
	if err != nil {
		return nil, err
	}

	// Return ID of both identity and entity
	return &logical.Response{
		Data: map[string]interface{}{
			"id":        identity.ID,
			"entity_id": entity.ID,
		},
	}, nil
}

// pathIdentityIDRead returns the properties of an identity for a given
// identity ID
func (i *identityStore) pathIdentityIDRead(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	identityID := d.Get("id").(string)
	if identityID == "" {
		return logical.ErrorResponse("missing identity id"), nil
	}

	identity, err := i.memDBIdentityByID(identityID)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	// Be sure that MountID is not returned here. Currently the structs tag
	// ignores the field while creating map. This behaviour should be retained
	// if the code here changes.
	return &logical.Response{
		Data: structs.New(identity).Map(),
	}, nil
}

// pathIdentityIDDelete deleted the identity for a given identity ID
func (i *identityStore) pathIdentityIDDelete(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	identityID := d.Get("id").(string)
	if identityID == "" {
		return logical.ErrorResponse("missing identity id"), nil
	}

	return nil, i.deleteIdentity(identityID)
}

// pathIdentityIDList lists the IDs of all the valid identities in the identity
// store
func (i *identityStore) pathIdentityIDList(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ws := memdb.NewWatchSet()
	iter, err := i.memDBIdentities(ws)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch iterator for identities in memdb: %v", err)
	}

	var identityIDs []string
	for {
		raw := iter.Next()
		if raw == nil {
			break
		}
		identityIDs = append(identityIDs, raw.(*identityIndexEntry).ID)
	}

	return logical.ListResponse(identityIDs), nil
}

var identityHelp = map[string][2]string{
	"identity": {
		"Create a new identity",
		"",
	},
	"identity-id": {
		"Update, read or delete an entity using identity ID",
		"",
	},
	"identity-id-list": {
		"List all the entity IDs",
		"",
	},
}

package vault

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// personaPaths returns the API endpoints to operate on personae.
// Following are the paths supported:
// persona - To register/modify a persona
// persona/id - To lookup, delete and list personae based on ID
func personaPaths(i *identityStore) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "persona",
			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Entity ID to which this persona belongs to",
				},
				"mount_path": {
					Type:        framework.TypeString,
					Description: "Mount path to which this persona belongs to",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the persona",
				},
				"metadata": {
					Type:        framework.TypeStringSlice,
					Description: "Metadata to be associated with the persona. Format should be a comma separated list of `key=value` pairs.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathPersonaRegister,
			},

			HelpSynopsis:    strings.TrimSpace(personaHelp["persona"][0]),
			HelpDescription: strings.TrimSpace(personaHelp["persona"][1]),
		},
		{
			Pattern: "persona/id/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "ID of the persona",
				},
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Entity ID to which this persona should be tied to",
				},
				"mount_path": {
					Type:        framework.TypeString,
					Description: "Mount path to which this persona belongs to",
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the persona",
				},
				"metadata": {
					Type:        framework.TypeStringSlice,
					Description: "Metadata to be associated with the persona. Format should be a comma separated list of `key=value` pairs.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: i.pathPersonaIDUpdate,
				logical.ReadOperation:   i.pathPersonaIDRead,
				logical.DeleteOperation: i.pathPersonaIDDelete,
			},

			HelpSynopsis:    strings.TrimSpace(personaHelp["persona-id"][0]),
			HelpDescription: strings.TrimSpace(personaHelp["persona-id"][1]),
		},
		{
			Pattern: "persona/id/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: i.pathPersonaIDList,
			},

			HelpSynopsis:    strings.TrimSpace(personaHelp["persona-id-list"][0]),
			HelpDescription: strings.TrimSpace(personaHelp["persona-id-list"][1]),
		},
	}
}

// pathPersonaRegister is used to register new persona
func (i *identityStore) pathPersonaRegister(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handlePersonaUpdateCommon(req, d, nil)
}

// pathPersonaIDUpdate is used to update a persona based on the given
// persona ID
func (i *identityStore) pathPersonaIDUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get persona id
	personaID := d.Get("id").(string)

	if personaID == "" {
		return logical.ErrorResponse("missing persona id"), nil
	}

	persona, err := i.memDBPersonaByID(personaID)
	if err != nil {
		return nil, err
	}
	if persona == nil {
		return logical.ErrorResponse("invalid persona id"), nil
	}

	return i.handlePersonaUpdateCommon(req, d, persona)
}

// handlePersonaUpdateCommon is used to update a persona
func (i *identityStore) handlePersonaUpdateCommon(req *logical.Request, d *framework.FieldData, persona *personaIndexEntry) (*logical.Response, error) {
	var err error
	var newPersona bool
	var entity *entityStorageEntry
	var previousEntity *entityStorageEntry

	// Persona will be nil when a new persona is being registered; create a
	// new struct in that case.
	if persona == nil {
		persona = &personaIndexEntry{}
		newPersona = true
	}

	// Get entity id
	entityID := d.Get("entity_id").(string)
	if entityID != "" {
		entity, err = i.memDBEntityByID(entityID)
		if err != nil {
			return nil, err
		}
		if entity == nil {
			return logical.ErrorResponse("invalid entity id"), nil
		}
	}

	// Get persona name
	personaName := d.Get("name").(string)
	if personaName == "" {
		return logical.ErrorResponse("missing persona name"), nil
	}

	// Get mount path to which the persona belongs to
	mountPath := d.Get("mount_path").(string)
	if mountPath == "" {
		return logical.ErrorResponse("missing mount path"), nil
	}

	// Get persona metadata

	// Accept metadata in the form of map[string]string to be able to index on
	// it
	var personaMetadata map[string]string
	personaMetadataRaw, ok := d.GetOk("metadata")
	if ok {
		personaMetadata, err = i.parseMetadata(personaMetadataRaw.([]string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("failed to parse persona metadata: %v", err)), nil
		}
	}

	mountValidationResp := i.validateMountPathFunc(mountPath)
	if mountValidationResp == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid mount path %q", mountPath)), nil
	}

	personaByFactors, err := i.memDBPersonaByFactors(mountValidationResp.MountID, personaName)
	if err != nil {
		return nil, err
	}

	if newPersona {
		if personaByFactors != nil {
			return logical.ErrorResponse("combination of mount path and persona name is already in use"), nil
		}

		// If this is a persona being tied to a non-existent entity, create
		// a new entity for it.
		if entity == nil {
			entity = &entityStorageEntry{
				Personae: []*personaIndexEntry{
					persona,
				},
			}
		} else {
			entity.Personae = append(entity.Personae, persona)
		}
	} else {
		// Verify that the combination of persona name and mount path is not
		// already tied to a different persona
		if personaByFactors != nil && personaByFactors.ID != persona.ID {
			return logical.ErrorResponse("combination of mount path and persona name is already in use"), nil
		}

		// Fetch the entity to which the persona is tied to
		existingEntity, err := i.memDBEntityByPersonaID(persona.ID)
		if err != nil {
			return nil, err
		}

		if existingEntity == nil {
			return nil, fmt.Errorf("persona is not associated with an entity")
		}

		if entity != nil && entity.ID != existingEntity.ID {
			// Persona should be transferred from 'existingEntity' to 'entity'
			i.deletePersonaFromEntity(existingEntity, persona)
			previousEntity = existingEntity
			entity.Personae = append(entity.Personae, persona)
		} else {
			// Update entity with modified persona
			err = i.updatePersonaInEntity(existingEntity, persona)
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
	persona.Name = personaName
	persona.Metadata = personaMetadata
	persona.MountID = mountValidationResp.MountID
	persona.MountType = mountValidationResp.MountType

	// Set the entity ID in the persona index. This should be done after
	// sanitizing entity.
	persona.EntityID = entity.ID

	// ID creation and other validations
	err = i.sanitizePersona(persona)
	if err != nil {
		return nil, err
	}

	// Index entity and its personae in MemDB and persist entity along with
	// personae in storage. If the persona is being transferred over from
	// one entity to another, previous entity needs to get refreshed in MemDB
	// and persisted in storage as well.
	err = i.upsertEntity(entity, previousEntity, true)
	if err != nil {
		return nil, err
	}

	// Return ID of both persona and entity
	return &logical.Response{
		Data: map[string]interface{}{
			"id":        persona.ID,
			"entity_id": entity.ID,
		},
	}, nil
}

// pathPersonaIDRead returns the properties of a persona for a given
// persona ID
func (i *identityStore) pathPersonaIDRead(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	personaID := d.Get("id").(string)
	if personaID == "" {
		return logical.ErrorResponse("missing persona id"), nil
	}

	persona, err := i.memDBPersonaByID(personaID)
	if err != nil {
		return nil, err
	}

	if persona == nil {
		return nil, nil
	}

	// Be sure that MountID is not returned here. Currently the structs tag
	// ignores the field while creating map. This behaviour should be retained
	// if the code here changes.
	return &logical.Response{
		Data: structs.New(persona).Map(),
	}, nil
}

// pathPersonaIDDelete deleted the persona for a given persona ID
func (i *identityStore) pathPersonaIDDelete(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	personaID := d.Get("id").(string)
	if personaID == "" {
		return logical.ErrorResponse("missing persona id"), nil
	}

	return nil, i.deletePersona(personaID)
}

// pathPersonaIDList lists the IDs of all the valid personae in the identity
// store
func (i *identityStore) pathPersonaIDList(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ws := memdb.NewWatchSet()
	iter, err := i.memDBPersonae(ws)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch iterator for personae in memdb: %v", err)
	}

	var personaIDs []string
	for {
		raw := iter.Next()
		if raw == nil {
			break
		}
		personaIDs = append(personaIDs, raw.(*personaIndexEntry).ID)
	}

	return logical.ListResponse(personaIDs), nil
}

var personaHelp = map[string][2]string{
	"persona": {
		"Create a new persona",
		"",
	},
	"persona-id": {
		"Update, read or delete an entity using persona ID",
		"",
	},
	"persona-id-list": {
		"List all the entity IDs",
		"",
	},
}

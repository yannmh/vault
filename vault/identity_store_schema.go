package vault

import (
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

func identityStoreSchema() *memdb.DBSchema {
	iStoreSchema := &memdb.DBSchema{
		Tables: make(map[string]*memdb.TableSchema),
	}

	schemas := []func() *memdb.TableSchema{
		identityTableSchema,
		entityTableSchema,
	}

	for _, schemaFunc := range schemas {
		schema := schemaFunc()
		if _, ok := iStoreSchema.Tables[schema.Name]; ok {
			panic(fmt.Sprintf("duplicate table name: %s", schema.Name))
		}
		iStoreSchema.Tables[schema.Name] = schema
	}

	return iStoreSchema
}

func identityTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "identities",
		Indexes: map[string]*memdb.IndexSchema{
			"id": &memdb.IndexSchema{
				Name:   "id",
				Unique: true,
				Indexer: &memdb.StringFieldIndex{
					Field: "ID",
				},
			},
			"entity_id": &memdb.IndexSchema{
				Name:   "entity_id",
				Unique: false,
				Indexer: &memdb.StringFieldIndex{
					Field: "EntityID",
				},
			},
			"mount_type": &memdb.IndexSchema{
				Name:   "mount_type",
				Unique: false,
				Indexer: &memdb.StringFieldIndex{
					Field: "MountType",
				},
			},
			"factors": &memdb.IndexSchema{
				Name:   "factors",
				Unique: true,
				Indexer: &memdb.CompoundIndex{
					Indexes: []memdb.Indexer{
						&memdb.StringFieldIndex{
							Field: "MountID",
						},
						&memdb.StringFieldIndex{
							Field: "Name",
						},
					},
				},
			},
			"metadata": &memdb.IndexSchema{
				Name:         "metadata",
				Unique:       false,
				AllowMissing: true,
				Indexer: &memdb.StringMapFieldIndex{
					Field: "Metadata",
				},
			},
		},
	}
}

func entityTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "entities",
		Indexes: map[string]*memdb.IndexSchema{
			"id": &memdb.IndexSchema{
				Name:   "id",
				Unique: true,
				Indexer: &memdb.StringFieldIndex{
					Field: "ID",
				},
			},
			"name": &memdb.IndexSchema{
				Name:   "name",
				Unique: true,
				Indexer: &memdb.StringFieldIndex{
					Field: "Name",
				},
			},
			"metadata": &memdb.IndexSchema{
				Name:         "metadata",
				Unique:       false,
				AllowMissing: true,
				Indexer: &memdb.StringMapFieldIndex{
					Field: "Metadata",
				},
			},
			"merged_entities": &memdb.IndexSchema{
				Name:         "merged_entities",
				Unique:       true,
				AllowMissing: true,
				Indexer: &memdb.StringSliceFieldIndex{
					Field: "MergedEntities",
				},
			},
		},
	}
}

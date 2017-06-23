package vault

import (
	"fmt"
	"strings"
	"sync"
	"time"

	memdb "github.com/hashicorp/go-memdb"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/consts"
	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
)

func (i *identityStore) parseMetadata(keyPairs []string) (map[string]string, error) {
	if len(keyPairs) == 0 {
		return nil, nil
	}

	metadata := make(map[string]string, len(keyPairs))
	for _, keyPair := range keyPairs {
		keyPairSlice := strings.SplitN(keyPair, ":", 2)
		if len(keyPairSlice) != 2 {
			return nil, fmt.Errorf("invalid key pair %q", keyPair)
		}
		metadata[keyPairSlice[0]] = keyPairSlice[1]
	}

	return metadata, nil
}

func (c *Core) loadEntities() error {
	if c.identityStore == nil {
		return fmt.Errorf("identity store is not setup")
	}

	return c.identityStore.loadEntities()
}

func (i *identityStore) loadEntities() error {
	// Accumulate existing entities
	i.logger.Debug("identity: loading entities")
	existing, err := logical.CollectKeys(i.storagePacker.View())
	if err != nil {
		return fmt.Errorf("failed to scan for entities: %v", err)
	}
	i.logger.Debug("identity: entities collected", "num_existing", len(existing))

	// Make the channels used for the worker pool
	broker := make(chan string)
	quit := make(chan bool)

	// Buffer these channels to prevent deadlocks
	errs := make(chan error, len(existing))
	result := make(chan *storageBucketEntry, len(existing))

	// Use a wait group
	wg := &sync.WaitGroup{}

	// Create 64 workers to distribute work to
	for j := 0; j < consts.ExpirationRestoreWorkerCount; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case bucketKey, ok := <-broker:
					// broker has been closed, we are done
					if !ok {
						return
					}

					bucketEntry, err := i.storagePacker.Get(bucketKey)
					if err != nil {
						errs <- err
						continue
					}

					// Write results out to the result channel
					result <- bucketEntry

				// quit early
				case <-quit:
					return
				}
			}
		}()
	}

	// Distribute the collected keys to the workers in a go routine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j, bucketKey := range existing {
			if j%500 == 0 {
				i.logger.Trace("identity: enities loading", "progress", j)
			}

			select {
			case <-quit:
				return

			default:
				broker <- bucketKey
			}
		}

		// Close the broker, causing worker routines to exit
		close(broker)
	}()

	// Restore each key by pulling from the result chan
	for j := 0; j < len(existing); j++ {
		select {
		case err := <-errs:
			// Close all go routines
			close(quit)

			return err

		case bucketEntry := <-result:
			// If there is no entry, nothing to restore
			if bucketEntry == nil {
				continue
			}

			for _, entity := range bucketEntry.Items {
				// Only update MemDB and don't hit the storage again
				err = i.upsertEntity(entity, nil, false)
				if err != nil {
					return fmt.Errorf("failed to update entity in MemDB: %v", err)
				}
			}
		}
	}

	// Let all go routines finish
	wg.Wait()

	if i.logger.IsInfo() {
		i.logger.Info("identity: entities restored")
	}

	return nil
}

// upsertEntity either creates or updates an existing entity. The operations
// will be updated in both MemDB and storage. If 'persist' is set to false,
// then storage will not be updated. When a persona is transferred from one
// entity to another, both the source and destination entities should get
// updated, in which case, callers should send in both entity and
// previousEntity.
func (i *identityStore) upsertEntity(entity *entityStorageEntry, previousEntity *entityStorageEntry, persist bool) error {
	var err error

	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	// Acquire the lock to modify the entity storage entry
	lock := locksutil.LockForKey(i.entityLocks, entity.ID)
	lock.Lock()
	defer lock.Unlock()

	// Create a MemDB transaction to update both persona and entity
	txn := i.db.Txn(true)
	defer txn.Abort()

	for _, persona := range entity.Personae {
		// Verify that persona is not associated to a different one already
		personaByFactors, err := i.memDBPersonaByFactors(persona.MountID, persona.Name)
		if err != nil {
			return err
		}

		if personaByFactors != nil && personaByFactors.EntityID != entity.ID {
			return fmt.Errorf("persona %q in already tied to a different entity %q", persona.ID, entity.ID, personaByFactors.EntityID)
		}

		// Insert or update persona in MemDB using the transaction created above
		err = i.memDBUpsertPersonaInTxn(txn, persona)
		if err != nil {
			return err
		}
	}

	// If previous entity is set, update it in MemDB and persist it
	if previousEntity != nil && persist {
		err = i.memDBUpsertEntityInTxn(txn, previousEntity)
		if err != nil {
			return err
		}

		// Persist the previous entity object
		err = i.storagePacker.PutItem(previousEntity)
		if err != nil {
			return err
		}
	}

	// Insert or update entity in MemDB using the transaction created above
	err = i.memDBUpsertEntityInTxn(txn, entity)
	if err != nil {
		return err
	}

	if persist {
		// Persist the entity object
		err = i.storagePacker.PutItem(entity)
		if err != nil {
			return err
		}
	}

	// Committing the transaction *after* successfully persisting entity
	txn.Commit()

	return nil
}

func (i *identityStore) deleteEntity(entityID string) error {
	var err error
	var entity *entityStorageEntry

	if entityID == "" {
		return fmt.Errorf("missing entity id")
	}

	// Since an entity ID is required to acquire the lock to modify the
	// storage, fetch the entity without acquiring the lock

	lockEntity, err := i.memDBEntityByID(entityID)
	if err != nil {
		return err
	}

	if lockEntity == nil {
		return nil
	}

	// Acquire the lock to modify the entity storage entry
	lock := locksutil.LockForKey(i.entityLocks, lockEntity.ID)
	lock.Lock()
	defer lock.Unlock()

	// Create a MemDB transaction to delete entity
	txn := i.db.Txn(true)
	defer txn.Abort()

	// Fetch the entity using its ID
	entity, err = i.memDBEntityByIDInTxn(txn, entityID)
	if err != nil {
		return err
	}

	// If there is no entity for the ID, do nothing
	if entity == nil {
		return nil
	}

	// Delete all the personae in the entity. This function will also remove
	// the corresponding persona indexes too.
	err = i.deletePersonaeInEntityInTxn(txn, entity, entity.Personae)
	if err != nil {
		return err
	}

	// Delete the entity using the same transaction
	err = i.memDBDeleteEntityInTxn(txn, entity)
	if err != nil {
		return err
	}

	// Delete the entity from storage
	err = i.storagePacker.DeleteItem(entity.ID)
	if err != nil {
		return err
	}

	// Committing the transaction *after* successfully deleting entity
	txn.Commit()

	return nil
}

func (i *identityStore) deletePersona(personaID string) error {
	var err error
	var persona *personaIndexEntry
	var entity *entityStorageEntry

	if personaID == "" {
		return fmt.Errorf("missing persona id")
	}

	// Since an entity ID is required to acquire the lock to modify the
	// storage, fetch the entity without acquiring the lock

	// Fetch the persona using its ID

	persona, err = i.memDBPersonaByID(personaID)
	if err != nil {
		return err
	}

	// If there is no persona for the ID, do nothing
	if persona == nil {
		return nil
	}

	// Find the entity to which the persona is tied to
	lockEntity, err := i.memDBEntityByPersonaID(persona.ID)
	if err != nil {
		return err
	}

	// If there is no entity tied to a valid persona, something is wrong
	if lockEntity == nil {
		return fmt.Errorf("persona not associated to an entity")
	}

	// Acquire the lock to modify the entity storage entry
	lock := locksutil.LockForKey(i.entityLocks, lockEntity.ID)
	lock.Lock()
	defer lock.Unlock()

	// Create a MemDB transaction to delete entity
	txn := i.db.Txn(true)
	defer txn.Abort()

	// Fetch the persona again after acquiring the lock using the transaction
	// created above
	persona, err = i.memDBPersonaByIDInTxn(txn, personaID)
	if err != nil {
		return err
	}

	// If there is no persona for the ID, do nothing
	if persona == nil {
		return nil
	}

	// Fetch the entity again after acquiring the lock using the transaction
	// created above
	entity, err = i.memDBEntityByPersonaIDInTxn(txn, persona.ID)
	if err != nil {
		return err
	}

	// If there is no entity tied to a valid persona, something is wrong
	if entity == nil {
		return fmt.Errorf("persona not associated to an entity")
	}

	// Lock switching should not end up in this code pointing to different
	// entities
	if entity.ID != entity.ID {
		return fmt.Errorf("operating on an entity to which the lock doesn't belong to")
	}

	personae := []*personaIndexEntry{
		persona,
	}

	// Delete persona from the entity object
	err = i.deletePersonaeInEntityInTxn(txn, entity, personae)
	if err != nil {
		return err
	}

	// Update the entity index in the entities table
	err = i.memDBUpsertEntityInTxn(txn, entity)
	if err != nil {
		return err
	}

	// Persist the entity object
	err = i.storagePacker.PutItem(entity)
	if err != nil {
		return err
	}

	// Committing the transaction *after* successfully updating entity in
	// storage
	txn.Commit()

	return nil
}

func (i *identityStore) memDBUpsertPersonaInTxn(txn *memdb.Txn, persona *personaIndexEntry) error {
	if txn == nil {
		return fmt.Errorf("nil txn")
	}

	if persona == nil {
		return fmt.Errorf("persona is nil")
	}

	personaRaw, err := txn.First("personae", "id", persona.ID)
	if err != nil {
		return fmt.Errorf("failed to lookup persona from memdb using persona id: %v", err)
	}

	if personaRaw != nil {
		err = txn.Delete("personae", personaRaw)
		if err != nil {
			return fmt.Errorf("failed to delete persona from memdb: %v", err)
		}
	}

	if err := txn.Insert("personae", persona); err != nil {
		return fmt.Errorf("failed to update persona into memdb: %v", err)
	}

	return nil
}

func (i *identityStore) memDBUpsertPersona(persona *personaIndexEntry) error {
	if persona == nil {
		return fmt.Errorf("persona is nil")
	}

	txn := i.db.Txn(true)
	defer txn.Abort()

	err := i.memDBUpsertPersonaInTxn(txn, persona)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

func (i *identityStore) memDBPersonaByEntityIDInTxn(txn *memdb.Txn, entityID string) (*personaIndexEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("missing entity id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	personaRaw, err := txn.First("personae", "entity_id", entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch persona from memdb using entity id: %v", err)
	}

	if personaRaw == nil {
		return nil, nil
	}

	persona, ok := personaRaw.(*personaIndexEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched persona")
	}

	return persona, nil
}

func (i *identityStore) memDBPersonaByEntityID(entityID string) (*personaIndexEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("missing entity id")
	}

	txn := i.db.Txn(false)

	return i.memDBPersonaByEntityIDInTxn(txn, entityID)
}

func (i *identityStore) memDBPersonaByIDInTxn(txn *memdb.Txn, personaID string) (*personaIndexEntry, error) {
	if personaID == "" {
		return nil, fmt.Errorf("missing persona id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	personaRaw, err := txn.First("personae", "id", personaID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch persona from memdb using persona id: %v", err)
	}

	if personaRaw == nil {
		return nil, nil
	}

	persona, ok := personaRaw.(*personaIndexEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched persona")
	}

	return persona, nil
}

func (i *identityStore) memDBPersonaByID(personaID string) (*personaIndexEntry, error) {
	if personaID == "" {
		return nil, fmt.Errorf("missing persona id")
	}

	txn := i.db.Txn(false)

	return i.memDBPersonaByIDInTxn(txn, personaID)
}

func (i *identityStore) memDBPersonaByFactors(mountID, personaName string) (*personaIndexEntry, error) {
	if personaName == "" {
		return nil, fmt.Errorf("missing persona name")
	}

	if mountID == "" {
		return nil, fmt.Errorf("missing mount path")
	}

	txn := i.db.Txn(false)
	personaRaw, err := txn.First("personae", "factors", mountID, personaName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch persona from memdb using factors: %v", err)
	}

	if personaRaw == nil {
		return nil, nil
	}

	persona, ok := personaRaw.(*personaIndexEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched persona")
	}

	return persona, nil
}

func (i *identityStore) memDBPersonaeByMetadata(filters map[string]string) ([]*personaIndexEntry, error) {
	if filters == nil {
		return nil, fmt.Errorf("map filter is nil")
	}

	tx := i.db.Txn(false)
	defer tx.Abort()

	var args []interface{}
	for key, value := range filters {
		args = append(args, key, value)
		break
	}

	personaeIter, err := tx.Get("personae", "metadata", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup personae using metadata: %v", err)
	}

	var personae []*personaIndexEntry
	for persona := personaeIter.Next(); persona != nil; persona = personaeIter.Next() {
		i := persona.(*personaIndexEntry)
		if len(filters) <= 1 || satisfiesMetadataFilters(i.Metadata, filters) {
			personae = append(personae, i)
		}
	}
	return personae, nil
}

func (i *identityStore) memDBDeletePersonaByID(personaID string) error {
	if personaID == "" {
		return nil
	}

	persona, err := i.memDBPersonaByID(personaID)
	if err != nil {
		return err
	}

	if persona == nil {
		return nil
	}

	return i.memDBDeletePersona(persona)
}

func (i *identityStore) memDBDeletePersonaInTxn(txn *memdb.Txn, persona *personaIndexEntry) error {
	var err error

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	if persona == nil {
		return nil
	}

	if persona != nil {
		err = txn.Delete("personae", persona)
		if err != nil {
			return fmt.Errorf("failed to delete persona from memdb: %v", err)
		}
	}

	return nil
}

func (i *identityStore) memDBDeletePersona(persona *personaIndexEntry) error {
	var err error
	if persona == nil {
		return nil
	}

	txn := i.db.Txn(true)
	defer txn.Abort()

	err = i.memDBDeletePersonaInTxn(txn, persona)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

func (i *identityStore) memDBPersonae(ws memdb.WatchSet) (memdb.ResultIterator, error) {
	txn := i.db.Txn(false)

	iter, err := txn.Get("personae", "id")
	if err != nil {
		return nil, err
	}

	ws.Add(iter.WatchCh())

	return iter, nil
}

func (i *identityStore) memDBUpsertEntityInTxn(txn *memdb.Txn, entity *entityStorageEntry) error {
	if txn == nil {
		return fmt.Errorf("nil txn")
	}

	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	entityRaw, err := txn.First("entities", "id", entity.ID)
	if err != nil {
		return fmt.Errorf("failed to lookup entity from memdb using entity id: %v", err)
	}

	if entityRaw != nil {
		err = txn.Delete("entities", entityRaw)
		if err != nil {
			return fmt.Errorf("failed to delete entity from memdb: %v", err)
		}
	}

	if err := txn.Insert("entities", entity); err != nil {
		return fmt.Errorf("failed to update entity into memdb: %v", err)
	}

	return nil
}

func (i *identityStore) memDBUpsertEntity(entity *entityStorageEntry) error {
	if entity == nil {
		return fmt.Errorf("entity to upsert is nil")
	}

	txn := i.db.Txn(true)
	defer txn.Abort()

	err := i.memDBUpsertEntityInTxn(txn, entity)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

func (i *identityStore) memDBEntityByIDInTxn(txn *memdb.Txn, entityID string) (*entityStorageEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("missing entity id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	entityRaw, err := txn.First("entities", "id", entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entity from memdb using entity id: %v", err)
	}

	if entityRaw == nil {
		return nil, nil
	}

	entity, ok := entityRaw.(*entityStorageEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched entity")
	}

	return entity, nil
}

func (i *identityStore) memDBEntityByID(entityID string) (*entityStorageEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("missing entity id")
	}

	txn := i.db.Txn(false)

	return i.memDBEntityByIDInTxn(txn, entityID)
}

func (i *identityStore) memDBEntityByNameInTxn(txn *memdb.Txn, entityName string) (*entityStorageEntry, error) {
	if entityName == "" {
		return nil, fmt.Errorf("missing entity name")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	entityRaw, err := txn.First("entities", "name", entityName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entity from memdb using entity name: %v", err)
	}

	if entityRaw == nil {
		return nil, nil
	}

	entity, ok := entityRaw.(*entityStorageEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched entity")
	}

	return entity, nil
}

func (i *identityStore) memDBEntityByName(entityName string) (*entityStorageEntry, error) {
	if entityName == "" {
		return nil, fmt.Errorf("missing entity name")
	}

	txn := i.db.Txn(false)

	return i.memDBEntityByNameInTxn(txn, entityName)
}

func (i *identityStore) memDBEntitiesByMetadata(filters map[string]string) ([]*entityStorageEntry, error) {
	if filters == nil {
		return nil, fmt.Errorf("map filter is nil")
	}

	tx := i.db.Txn(false)
	defer tx.Abort()

	var args []interface{}
	for key, value := range filters {
		args = append(args, key, value)
		break
	}

	entitiesIter, err := tx.Get("entities", "metadata", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup entities using metadata: %v", err)
	}

	var entities []*entityStorageEntry
	for entity := entitiesIter.Next(); entity != nil; entity = entitiesIter.Next() {
		i := entity.(*entityStorageEntry)
		if len(filters) <= 1 || satisfiesMetadataFilters(i.Metadata, filters) {
			entities = append(entities, i)
		}
	}
	return entities, nil
}

func (i *identityStore) memDBEntityByMergedEntityIDInTxn(txn *memdb.Txn, mergedEntityID string) (*entityStorageEntry, error) {
	if mergedEntityID == "" {
		return nil, fmt.Errorf("missing merged entity id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	entityRaw, err := txn.First("entities", "merged_entities", mergedEntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entity from memdb using merged entity id: %v", err)
	}

	if entityRaw == nil {
		return nil, nil
	}

	entity, ok := entityRaw.(*entityStorageEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched entity")
	}

	return entity, nil
}

func (i *identityStore) memDBEntityByMergedEntityID(mergedEntityID string) (*entityStorageEntry, error) {
	if mergedEntityID == "" {
		return nil, fmt.Errorf("missing merged entity id")
	}

	txn := i.db.Txn(false)

	return i.memDBEntityByMergedEntityIDInTxn(txn, mergedEntityID)
}

func (i *identityStore) memDBEntityByPersonaIDInTxn(txn *memdb.Txn, personaID string) (*entityStorageEntry, error) {
	if personaID == "" {
		return nil, fmt.Errorf("missing persona id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	persona, err := i.memDBPersonaByIDInTxn(txn, personaID)
	if err != nil {
		return nil, err
	}

	if persona == nil {
		return nil, nil
	}

	return i.memDBEntityByIDInTxn(txn, persona.EntityID)
}

func (i *identityStore) memDBEntityByPersonaID(personaID string) (*entityStorageEntry, error) {
	if personaID == "" {
		return nil, fmt.Errorf("missing persona id")
	}

	txn := i.db.Txn(false)

	return i.memDBEntityByPersonaIDInTxn(txn, personaID)
}

func (i *identityStore) memDBDeleteEntityByID(entityID string) error {
	if entityID == "" {
		return nil
	}

	entity, err := i.memDBEntityByID(entityID)
	if err != nil {
		return err
	}

	if entity == nil {
		return nil
	}

	return i.memDBDeleteEntity(entity)
}

func (i *identityStore) memDBDeleteEntityInTxn(txn *memdb.Txn, entity *entityStorageEntry) error {
	var err error

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	if entity == nil {
		return nil
	}

	if entity != nil {
		err = txn.Delete("entities", entity)
		if err != nil {
			return fmt.Errorf("failed to delete entity from memdb: %v", err)
		}
	}

	return nil
}

func (i *identityStore) memDBDeleteEntity(entity *entityStorageEntry) error {
	var err error
	if entity == nil {
		return nil
	}

	txn := i.db.Txn(true)
	defer txn.Abort()

	err = i.memDBDeleteEntityInTxn(txn, entity)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

func (i *identityStore) memDBEntities(ws memdb.WatchSet) (memdb.ResultIterator, error) {
	txn := i.db.Txn(false)

	iter, err := txn.Get("entities", "id")
	if err != nil {
		return nil, err
	}

	ws.Add(iter.WatchCh())

	return iter, nil
}

func (i *identityStore) sanitizePersona(persona *personaIndexEntry) error {
	var err error

	if persona == nil {
		return fmt.Errorf("persona is nil")
	}

	// Persona must always be tied to an entity
	if persona.EntityID == "" {
		return fmt.Errorf("missing entity id")
	}

	// Persona must have a name
	if persona.Name == "" {
		return fmt.Errorf("missing persona name %q", persona.Name)
	}

	// Persona metadata should always be map[string]string
	err = validateMetadata(persona.Metadata)
	if err != nil {
		return fmt.Errorf("invalid persona metadata: %v", err)
	}

	// Create an ID if there isn't one already
	if persona.ID == "" {
		persona.ID, err = uuid.GenerateUUID()
		if err != nil {
			return fmt.Errorf("failed to generate persona id")
		}
	}

	// Set the creation and last update times
	if persona.CreationTime.IsZero() {
		persona.CreationTime = time.Now()
		persona.LastUpdateTime = persona.CreationTime
	} else {
		persona.LastUpdateTime = time.Now()
	}

	return nil
}

func sanitizeEntity(entity *entityStorageEntry) error {
	var err error

	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	// Create an ID if there isn't one already
	if entity.ID == "" {
		entity.ID, err = uuid.GenerateUUID()
		if err != nil {
			return fmt.Errorf("failed to generate entity id")
		}
	}

	// Create a name if there isn't one already
	if entity.Name == "" {
		randomName, err := uuid.GenerateUUID()
		if err != nil {
			return fmt.Errorf("failed to generate entity name")
		}
		entity.Name = "entity-" + randomName
	}

	// Entity metadata should always be map[string]string
	err = validateMetadata(entity.Metadata)
	if err != nil {
		return fmt.Errorf("invalid entity metadata: %v", err)
	}

	// Set the creation and last update times
	if entity.CreationTime.IsZero() {
		entity.CreationTime = time.Now()
		entity.LastUpdateTime = entity.CreationTime
	} else {
		entity.LastUpdateTime = time.Now()
	}

	return nil
}

func (i *identityStore) deletePersonaeInEntityInTxn(txn *memdb.Txn, entity *entityStorageEntry, personae []*personaIndexEntry) error {
	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	var remainList []*personaIndexEntry
	var removeList []*personaIndexEntry

	for _, item := range personae {
		for _, persona := range entity.Personae {
			if persona.ID == item.ID {
				removeList = append(removeList, persona)
			} else {
				remainList = append(remainList, persona)
			}
		}
	}

	// Remove indentity indices from personae table for those that needs to
	// be removed
	for _, persona := range removeList {
		personaToBeRemoved, err := i.memDBPersonaByIDInTxn(txn, persona.ID)
		if err != nil {
			return err
		}
		if personaToBeRemoved == nil {
			return fmt.Errorf("persona was not indexed")
		}
		err = i.memDBDeletePersonaInTxn(txn, personaToBeRemoved)
		if err != nil {
			return err
		}
	}

	// Update the entity with remaining items
	entity.Personae = remainList

	return nil
}

func (i *identityStore) deletePersonaFromEntity(entity *entityStorageEntry, persona *personaIndexEntry) error {
	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if persona == nil {
		return fmt.Errorf("persona is nil")
	}

	for personaIndex, item := range entity.Personae {
		if item.ID == persona.ID {
			entity.Personae = append(entity.Personae[:personaIndex], entity.Personae[personaIndex+1:]...)
			break
		}
	}

	return nil
}

func (i *identityStore) updatePersonaInEntity(entity *entityStorageEntry, persona *personaIndexEntry) error {
	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if persona == nil {
		return fmt.Errorf("persona is nil")
	}

	personaFound := false
	for personaIndex, item := range entity.Personae {
		if item.ID == persona.ID {
			personaFound = true
			entity.Personae[personaIndex] = persona
		}
	}

	if !personaFound {
		return fmt.Errorf("persona does not exist in entity")
	}

	return nil
}

// This function is not used currently. Leaving this here in hope that it will
// be of use. When you are reading this, if this comment is atleast a year old,
// delete this function.
func (i *identityStore) memDBAssociatePersonaeToEntityInTxn(txn *memdb.Txn, entity *entityStorageEntry, personae []*personaIndexEntry) error {
	var err error

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if len(personae) == 0 {
		return fmt.Errorf("missing personae")
	}

	newPersonae := make([]*personaIndexEntry, len(personae))
	copy(newPersonae, personae)

	// Verify that given personae do not already belong to other entities
	for _, persona := range personae {
		entityByPersonaID, err := i.memDBEntityByPersonaID(persona.ID)
		if err != nil {
			return err
		}
		if entityByPersonaID != nil && entityByPersonaID.ID != entity.ID {
			return fmt.Errorf("persona %q is already tied to a different entity %q", persona.ID, entityByPersonaID.ID)
		}
	}

	// This is a N^2 algorithm. Improve later.
	for _, oldPersona := range entity.Personae {
		foundIndex := -1
		for idx, newPersona := range personae {
			if oldPersona.ID == newPersona.ID {
				foundIndex = idx
			}
		}

		if foundIndex != -1 {
			personae = append(personae[:foundIndex], personae[foundIndex+1:]...)
			continue
		}

		personaToBeRemoved, err := i.memDBPersonaByID(oldPersona.ID)
		if err != nil {
			return err
		}
		if personaToBeRemoved == nil {
			return fmt.Errorf("persona was not indexed")
		}
		err = i.memDBDeletePersonaInTxn(txn, personaToBeRemoved)
		if err != nil {
			return err
		}
	}

	for _, newPersona := range personae {
		err = i.memDBUpsertPersonaInTxn(txn, newPersona)
		if err != nil {
			return err
		}
	}

	entity.Personae = newPersonae

	return nil
}

// validateMeta validates a set of key/value pairs from the agent config
func validateMetadata(meta map[string]string) error {
	if len(meta) > metaMaxKeyPairs {
		return fmt.Errorf("metadata cannot contain more than %d key/value pairs", metaMaxKeyPairs)
	}

	for key, value := range meta {
		if err := validateMetaPair(key, value); err != nil {
			return fmt.Errorf("failed to load metadata pair (%q, %q): %v", key, value, err)
		}
	}

	return nil
}

// validateMetaPair checks that the given key/value pair is in a valid format
func validateMetaPair(key, value string) error {
	if key == "" {
		return fmt.Errorf("key cannot be blank")
	}
	if !metaKeyFormatRegEx(key) {
		return fmt.Errorf("key contains invalid characters")
	}
	if len(key) > metaKeyMaxLength {
		return fmt.Errorf("key is too long (limit: %d characters)", metaKeyMaxLength)
	}
	if strings.HasPrefix(key, metaKeyReservedPrefix) {
		return fmt.Errorf("key prefix %q is reserved for internal use", metaKeyReservedPrefix)
	}
	if len(value) > metaValueMaxLength {
		return fmt.Errorf("value is too long (limit: %d characters)", metaValueMaxLength)
	}
	return nil
}

// satisfiesMetadataFilters returns true if the metadata map contains the given filters
func satisfiesMetadataFilters(meta map[string]string, filters map[string]string) bool {
	for key, value := range filters {
		if v, ok := meta[key]; !ok || v != value {
			return false
		}
	}
	return true
}

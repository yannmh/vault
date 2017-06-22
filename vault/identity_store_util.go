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
// then storage will not be updated. When an identity is transferred from one
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

	// Create a MemDB transaction to update both identity and entity
	txn := i.db.Txn(true)
	defer txn.Abort()

	for _, identity := range entity.Identities {
		// Verify that identity is not associated to a different one already
		identityByFactors, err := i.memDBIdentityByFactors(identity.MountID, identity.Name)
		if err != nil {
			return err
		}

		if identityByFactors != nil && identityByFactors.EntityID != entity.ID {
			return fmt.Errorf("identity %q in already tied to a different entity %q", identity.ID, entity.ID, identityByFactors.EntityID)
		}

		// Insert or update identity in MemDB using the transaction created above
		err = i.memDBUpsertIdentityInTxn(txn, identity)
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

	// Delete all the identities in the entity. This function will also remove
	// the corresponding identity indexes too.
	err = i.deleteIdentitiesInEntityInTxn(txn, entity, entity.Identities)
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

func (i *identityStore) deleteIdentity(identityID string) error {
	var err error
	var identity *identityIndexEntry
	var entity *entityStorageEntry

	if identityID == "" {
		return fmt.Errorf("missing identity id")
	}

	// Since an entity ID is required to acquire the lock to modify the
	// storage, fetch the entity without acquiring the lock

	// Fetch the identity using its ID

	identity, err = i.memDBIdentityByID(identityID)
	if err != nil {
		return err
	}

	// If there is no identity for the ID, do nothing
	if identity == nil {
		return nil
	}

	// Find the entity to which the identity is tied to
	lockEntity, err := i.memDBEntityByIdentityID(identity.ID)
	if err != nil {
		return err
	}

	// If there is no entity tied to a valid identity, something is wrong
	if lockEntity == nil {
		return fmt.Errorf("identity not associated to an entity")
	}

	// Acquire the lock to modify the entity storage entry
	lock := locksutil.LockForKey(i.entityLocks, lockEntity.ID)
	lock.Lock()
	defer lock.Unlock()

	// Create a MemDB transaction to delete entity
	txn := i.db.Txn(true)
	defer txn.Abort()

	// Fetch the identity again after acquiring the lock using the transaction
	// created above
	identity, err = i.memDBIdentityByIDInTxn(txn, identityID)
	if err != nil {
		return err
	}

	// If there is no identity for the ID, do nothing
	if identity == nil {
		return nil
	}

	// Fetch the entity again after acquiring the lock using the transaction
	// created above
	entity, err = i.memDBEntityByIdentityIDInTxn(txn, identity.ID)
	if err != nil {
		return err
	}

	// If there is no entity tied to a valid identity, something is wrong
	if entity == nil {
		return fmt.Errorf("identity not associated to an entity")
	}

	// Lock switching should not end up in this code pointing to different
	// entities
	if entity.ID != entity.ID {
		return fmt.Errorf("operating on an entity to which the lock doesn't belong to")
	}

	identities := []*identityIndexEntry{
		identity,
	}

	// Delete identity from the entity object
	err = i.deleteIdentitiesInEntityInTxn(txn, entity, identities)
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

func (i *identityStore) memDBUpsertIdentityInTxn(txn *memdb.Txn, identity *identityIndexEntry) error {
	if txn == nil {
		return fmt.Errorf("nil txn")
	}

	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	identityRaw, err := txn.First("identities", "id", identity.ID)
	if err != nil {
		return fmt.Errorf("failed to lookup identity from memdb using identity id: %v", err)
	}

	if identityRaw != nil {
		err = txn.Delete("identities", identityRaw)
		if err != nil {
			return fmt.Errorf("failed to delete identity from memdb: %v", err)
		}
	}

	if err := txn.Insert("identities", identity); err != nil {
		return fmt.Errorf("failed to update identity into memdb: %v", err)
	}

	return nil
}

func (i *identityStore) memDBUpsertIdentity(identity *identityIndexEntry) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	txn := i.db.Txn(true)
	defer txn.Abort()

	err := i.memDBUpsertIdentityInTxn(txn, identity)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

func (i *identityStore) memDBIdentityByEntityIDInTxn(txn *memdb.Txn, entityID string) (*identityIndexEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("missing entity id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	identityRaw, err := txn.First("identities", "entity_id", entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity from memdb using entity id: %v", err)
	}

	if identityRaw == nil {
		return nil, nil
	}

	identity, ok := identityRaw.(*identityIndexEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched identity")
	}

	return identity, nil
}

func (i *identityStore) memDBIdentityByEntityID(entityID string) (*identityIndexEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("missing entity id")
	}

	txn := i.db.Txn(false)

	return i.memDBIdentityByEntityIDInTxn(txn, entityID)
}

func (i *identityStore) memDBIdentityByIDInTxn(txn *memdb.Txn, identityID string) (*identityIndexEntry, error) {
	if identityID == "" {
		return nil, fmt.Errorf("missing identity id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	identityRaw, err := txn.First("identities", "id", identityID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity from memdb using identity id: %v", err)
	}

	if identityRaw == nil {
		return nil, nil
	}

	identity, ok := identityRaw.(*identityIndexEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched identity")
	}

	return identity, nil
}

func (i *identityStore) memDBIdentityByID(identityID string) (*identityIndexEntry, error) {
	if identityID == "" {
		return nil, fmt.Errorf("missing identity id")
	}

	txn := i.db.Txn(false)

	return i.memDBIdentityByIDInTxn(txn, identityID)
}

func (i *identityStore) memDBIdentityByFactors(mountID, identityName string) (*identityIndexEntry, error) {
	if identityName == "" {
		return nil, fmt.Errorf("missing identity name")
	}

	if mountID == "" {
		return nil, fmt.Errorf("missing mount path")
	}

	txn := i.db.Txn(false)
	identityRaw, err := txn.First("identities", "factors", mountID, identityName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity from memdb using factors: %v", err)
	}

	if identityRaw == nil {
		return nil, nil
	}

	identity, ok := identityRaw.(*identityIndexEntry)
	if !ok {
		return nil, fmt.Errorf("failed to declare the type of fetched identity")
	}

	return identity, nil
}

func (i *identityStore) memDBIdentitiesByMetadata(filters map[string]string) ([]*identityIndexEntry, error) {
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

	identitiesIter, err := tx.Get("identities", "metadata", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup identities using metadata: %v", err)
	}

	var identities []*identityIndexEntry
	for identity := identitiesIter.Next(); identity != nil; identity = identitiesIter.Next() {
		i := identity.(*identityIndexEntry)
		if len(filters) <= 1 || satisfiesMetadataFilters(i.Metadata, filters) {
			identities = append(identities, i)
		}
	}
	return identities, nil
}

func (i *identityStore) memDBDeleteIdentityByID(identityID string) error {
	if identityID == "" {
		return nil
	}

	identity, err := i.memDBIdentityByID(identityID)
	if err != nil {
		return err
	}

	if identity == nil {
		return nil
	}

	return i.memDBDeleteIdentity(identity)
}

func (i *identityStore) memDBDeleteIdentityInTxn(txn *memdb.Txn, identity *identityIndexEntry) error {
	var err error

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	if identity == nil {
		return nil
	}

	if identity != nil {
		err = txn.Delete("identities", identity)
		if err != nil {
			return fmt.Errorf("failed to delete identity from memdb: %v", err)
		}
	}

	return nil
}

func (i *identityStore) memDBDeleteIdentity(identity *identityIndexEntry) error {
	var err error
	if identity == nil {
		return nil
	}

	txn := i.db.Txn(true)
	defer txn.Abort()

	err = i.memDBDeleteIdentityInTxn(txn, identity)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

func (i *identityStore) memDBIdentities(ws memdb.WatchSet) (memdb.ResultIterator, error) {
	txn := i.db.Txn(false)

	iter, err := txn.Get("identities", "id")
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

func (i *identityStore) memDBEntityByIdentityIDInTxn(txn *memdb.Txn, identityID string) (*entityStorageEntry, error) {
	if identityID == "" {
		return nil, fmt.Errorf("missing identity id")
	}

	if txn == nil {
		return nil, fmt.Errorf("txn is nil")
	}

	identity, err := i.memDBIdentityByIDInTxn(txn, identityID)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	return i.memDBEntityByIDInTxn(txn, identity.EntityID)
}

func (i *identityStore) memDBEntityByIdentityID(identityID string) (*entityStorageEntry, error) {
	if identityID == "" {
		return nil, fmt.Errorf("missing identity id")
	}

	txn := i.db.Txn(false)

	return i.memDBEntityByIdentityIDInTxn(txn, identityID)
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

func (i *identityStore) sanitizeIdentity(identity *identityIndexEntry) error {
	var err error

	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	// Identity must always be tied to an entity
	if identity.EntityID == "" {
		return fmt.Errorf("missing entity id")
	}

	// Identity must have a name
	if identity.Name == "" {
		return fmt.Errorf("missing identity name %q", identity.Name)
	}

	// Identity metadata should always be map[string]string
	err = validateMetadata(identity.Metadata)
	if err != nil {
		return fmt.Errorf("invalid identity metadata: %v", err)
	}

	// Create an ID if there isn't one already
	if identity.ID == "" {
		identity.ID, err = uuid.GenerateUUID()
		if err != nil {
			return fmt.Errorf("failed to generate identity id")
		}
	}

	// Set the creation and last update times
	if identity.CreationTime.IsZero() {
		identity.CreationTime = time.Now()
		identity.LastUpdateTime = identity.CreationTime
	} else {
		identity.LastUpdateTime = time.Now()
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

func (i *identityStore) deleteIdentitiesInEntityInTxn(txn *memdb.Txn, entity *entityStorageEntry, identities []*identityIndexEntry) error {
	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	var remainList []*identityIndexEntry
	var removeList []*identityIndexEntry

	for _, item := range identities {
		for _, identity := range entity.Identities {
			if identity.ID == item.ID {
				removeList = append(removeList, identity)
			} else {
				remainList = append(remainList, identity)
			}
		}
	}

	// Remove indentity indices from identities table for those that needs to
	// be removed
	for _, identity := range removeList {
		identityToBeRemoved, err := i.memDBIdentityByIDInTxn(txn, identity.ID)
		if err != nil {
			return err
		}
		if identityToBeRemoved == nil {
			return fmt.Errorf("identity was not indexed")
		}
		err = i.memDBDeleteIdentityInTxn(txn, identityToBeRemoved)
		if err != nil {
			return err
		}
	}

	// Update the entity with remaining items
	entity.Identities = remainList

	return nil
}

func (i *identityStore) deleteIdentityFromEntity(entity *entityStorageEntry, identity *identityIndexEntry) error {
	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	for identityIndex, item := range entity.Identities {
		if item.ID == identity.ID {
			entity.Identities = append(entity.Identities[:identityIndex], entity.Identities[identityIndex+1:]...)
			break
		}
	}

	return nil
}

func (i *identityStore) updateIdentityInEntity(entity *entityStorageEntry, identity *identityIndexEntry) error {
	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	identityFound := false
	for identityIndex, item := range entity.Identities {
		if item.ID == identity.ID {
			identityFound = true
			entity.Identities[identityIndex] = identity
		}
	}

	if !identityFound {
		return fmt.Errorf("identity does not exist in entity")
	}

	return nil
}

// This function is not used currently. Leaving this here in hope that it will
// be of use. When you are reading this, if this comment is atleast a year old,
// delete this function.
func (i *identityStore) memDBAssociateIdentitiesToEntityInTxn(txn *memdb.Txn, entity *entityStorageEntry, identities []*identityIndexEntry) error {
	var err error

	if txn == nil {
		return fmt.Errorf("txn is nil")
	}

	if entity == nil {
		return fmt.Errorf("entity is nil")
	}

	if len(identities) == 0 {
		return fmt.Errorf("missing identities")
	}

	newIdentities := make([]*identityIndexEntry, len(identities))
	copy(newIdentities, identities)

	// Verify that given identities do not already belong to other entities
	for _, identity := range identities {
		entityByIdentityID, err := i.memDBEntityByIdentityID(identity.ID)
		if err != nil {
			return err
		}
		if entityByIdentityID != nil && entityByIdentityID.ID != entity.ID {
			return fmt.Errorf("identity %q is already tied to a different entity %q", identity.ID, entityByIdentityID.ID)
		}
	}

	// This is a N^2 algorithm. Improve later.
	for _, oldIdentity := range entity.Identities {
		foundIndex := -1
		for idx, newIdentity := range identities {
			if oldIdentity.ID == newIdentity.ID {
				foundIndex = idx
			}
		}

		if foundIndex != -1 {
			identities = append(identities[:foundIndex], identities[foundIndex+1:]...)
			continue
		}

		identityToBeRemoved, err := i.memDBIdentityByID(oldIdentity.ID)
		if err != nil {
			return err
		}
		if identityToBeRemoved == nil {
			return fmt.Errorf("identity was not indexed")
		}
		err = i.memDBDeleteIdentityInTxn(txn, identityToBeRemoved)
		if err != nil {
			return err
		}
	}

	for _, newIdentity := range identities {
		err = i.memDBUpsertIdentityInTxn(txn, newIdentity)
		if err != nil {
			return err
		}
	}

	entity.Identities = newIdentities

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

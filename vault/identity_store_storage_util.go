package vault

import (
	"crypto/md5"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/snappy"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	log "github.com/mgutz/logxi/v1"
)

const (
	bucketCount          = 256
	packerConfigLocation = "packerconfig"
)

// storagePacker packs the logical storage entries into a specific number of
// buckets by hashing its key and indexing based on the hash value. Currently
// this supports only 256 bucket entries and hence relies on the first byte of
// the hash value for indexing.
type storagePacker struct {
	config        *storagePackerConfig
	view          logical.Storage
	hashLock      sync.RWMutex
	logger        log.Logger
	configPersist sync.Once
}

// storagePackerConfig specifies the properties of the packer
type storagePackerConfig struct {
	Location   string    `json:"location" structs:"location" mapstructure:"location"`
	HashFunc   hash.Hash `json:"hash_func" structs:"hash_func" mapstructure:"hash_func"`
	ViewPrefix string    `json:"view_prefix" structs:"view_prefix" mapstructure:"view_prefix"`
	NumBuckets int       `json:"num_buckets" structs:"num_buckets" mapstructure:"num_buckets"`
}

// configStorageEntry contains the properties of packer that needs to survive
// reboot cycles
type configStorageEntry struct {
	NumBuckets int    `json:"num_buckets" structs:"num_buckets" mapstructure:"num_buckets"`
	ViewPrefix string `json:"view_prefix" structs:"view_prefix" mapstructure:"view_prefix"`
}

// storageBucketEntry represents a bucket which holds many storage entries
type storageBucketEntry struct {
	Key   string                `json:"key" structs:"key" mapstructure:"key"`
	Items []*entityStorageEntry `json:"items" structs:"items" mapstructure:"items"`
}

// persistPackerConfigOnceFunc stores the packer configuration in the storage
func (s *storagePacker) persistPackerConfigOnceFunc() {
	// Prepare the values that needs to get persisted
	configStorageEntry := &configStorageEntry{
		NumBuckets: s.config.NumBuckets,
		ViewPrefix: s.config.ViewPrefix,
	}

	entry, err := logical.StorageEntryJSON(s.config.Location, configStorageEntry)
	if err != nil {
		s.logger.Error("failed to create storage entry for storage packer properties", "error", err)
		return
	}

	// Persist the packer config properties
	err = s.view.Put(entry)
	if err != nil {
		s.logger.Error("failed to persist storage packer properties", "error", err)
		return
	}
}

// View returns the storage view configured to be used by the packer
func (s *storagePacker) View() logical.Storage {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)
	return s.view
}

// Get returns a bucket entry for a given bucket entry key
func (s *storagePacker) Get(bucketEntryKey string) (*storageBucketEntry, error) {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)

	if bucketEntryKey == "" {
		return nil, fmt.Errorf("missing bucket entry key")
	}

	// When trying to load entities during startup, scanning the view will
	// attempt a read on the packer config file as a bucket entry; ignore it.
	// There won't be a bucket entry with this same prefix as it is a reserved
	// keyword.
	if strings.HasPrefix(bucketEntryKey, packerConfigLocation) {
		return nil, nil
	}

	// Read from the underlying view
	storageEntry, err := s.view.Get(bucketEntryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read packed storage entry: %v", err)
	}
	if storageEntry == nil {
		return nil, nil
	}

	// Decompress the stored value
	decompressedBucketEntryBytes, err := snappy.Decode(nil, storageEntry.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress packed storage entry: %v", err)
	}

	// JSON decode it
	bucketEntry := &storageBucketEntry{}
	err = jsonutil.DecodeJSON(decompressedBucketEntryBytes, bucketEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode packed storage entry: %v", err)
	}

	return bucketEntry, nil
}

// upsert either inserts a new entry to the bucket or updates an existing one
// if an entry with a matching key is already present.
func (s *storageBucketEntry) upsert(entry *entityStorageEntry) error {
	if s == nil {
		return fmt.Errorf("nil storage bucket entry")
	}

	if entry == nil {
		return fmt.Errorf("nil entry")
	}

	if entry.ID == "" {
		return fmt.Errorf("missing entity ID")
	}

	// Look for an entry with matching key and don't modify the collection
	// while iterating
	foundIdx := -1
	for itemIdx, item := range s.Items {
		if item.ID == entry.ID {
			foundIdx = itemIdx
			break
		}
	}

	// If there is no match, append the entry, otherwise update it
	if foundIdx == -1 {
		s.Items = append(s.Items, entry)
	} else {
		s.Items[foundIdx] = entry
	}

	return nil
}

// BucketIndex returns the bucket key index for a given storage entry key
func (s *storagePacker) BucketIndex(key string) uint8 {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)

	s.hashLock.Lock()
	defer s.hashLock.Unlock()
	s.config.HashFunc.Reset()
	s.config.HashFunc.Write([]byte(key))
	return uint8(s.config.HashFunc.Sum(nil)[0])
}

// BucketKey returns the bucket key for a given entity ID
func (s *storagePacker) BucketKey(entityID string) string {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)
	return strconv.Itoa(int(s.BucketIndex(entityID)))
}

// DeleteItem removes the storage entry which the given key refers to from its
// corresponding bucket.
func (s *storagePacker) DeleteItem(entityID string) error {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)

	if entityID == "" {
		return fmt.Errorf("empty entity ID")
	}

	// Get the bucket key
	bucketKey := s.BucketKey(entityID)

	// Prepend the view prefix
	bucketEntryKey := s.config.ViewPrefix + bucketKey

	// Read from underlying view
	storageEntry, err := s.view.Get(bucketEntryKey)
	if err != nil {
		return fmt.Errorf("failed to read packed storage entry: %v", err)
	}
	if storageEntry == nil {
		return nil
	}

	// Decompress the stored value
	decompressedBucketEntryBytes, err := snappy.Decode(nil, storageEntry.Value)
	if err != nil {
		return fmt.Errorf("failed to decompress packed storage entry: %v", err)
	}

	// JSON decode it
	bucketEntry := &storageBucketEntry{}
	err = jsonutil.DecodeJSON(decompressedBucketEntryBytes, bucketEntry)
	if err != nil {
		return fmt.Errorf("failed to decode packed storage entry: %v", err)
	}

	// Look for a matching storage entry
	foundIdx := -1
	for itemIdx, item := range bucketEntry.Items {
		if item.ID == entityID {
			foundIdx = itemIdx
		}
	}

	// If there is a match, remove it from the collection and persist the
	// resulting collection
	if foundIdx != -1 {
		bucketEntry.Items = append(bucketEntry.Items[:foundIdx], bucketEntry.Items[foundIdx+1:]...)

		// Persist bucket entry only if there is an update
		err = s.Put(bucketEntry)
		if err != nil {
			return err
		}
	}

	return nil
}

// Put stores a packed bucket entry
func (s *storagePacker) Put(bucketEntry *storageBucketEntry) error {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)

	if bucketEntry == nil {
		return fmt.Errorf("nil bucket entry")
	}

	if bucketEntry.Key == "" {
		return fmt.Errorf("missing key")
	}

	// Packer configuration location is a reserved keyword. Don't allow storing
	// a bucket entry for this prefix.
	if strings.HasPrefix(bucketEntry.Key, packerConfigLocation) {
		return fmt.Errorf("bucket entry prefix of %q is reserved for packer configuration", packerConfigLocation)
	}

	// JSON encode before compressing
	bucketEntryBytes, err := jsonutil.EncodeJSON(bucketEntry)
	if err != nil {
		return fmt.Errorf("failed to json encode packed storage entry: %v", err)
	}

	// Fast compression
	compressedBucketEntryBytes := snappy.Encode(nil, bucketEntryBytes)

	// Store the compressed value
	err = s.view.Put(&logical.StorageEntry{
		Key:   bucketEntry.Key,
		Value: compressedBucketEntryBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to persist packed storage entry: %v", err)
	}

	return nil
}

// GetItem fetches the storage entry for a given key from its corresponding
// bucket.
func (s *storagePacker) GetItem(entityID string) (*entityStorageEntry, error) {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)

	if entityID == "" {
		return nil, fmt.Errorf("empty entity ID")
	}

	bucketKey := s.BucketKey(entityID)
	bucketEntryKey := s.config.ViewPrefix + bucketKey

	// Fetch the bucket entry
	bucketEntry, err := s.Get(bucketEntryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read packed storage entry: %v", err)
	}

	// Look for a matching storage entry in the bucket items
	for _, item := range bucketEntry.Items {
		if item.ID == entityID {
			return item, nil
		}
	}

	return nil, nil
}

// PutItem stores a storage entry in its corresponding bucket
func (s *storagePacker) PutItem(entity *entityStorageEntry) error {
	s.configPersist.Do(s.persistPackerConfigOnceFunc)

	if entity == nil {
		return fmt.Errorf("nil entity")
	}

	if entity.ID == "" {
		return fmt.Errorf("missing ID in entity")
	}

	var err error

	bucketKey := s.BucketKey(entity.ID)

	bucketEntryKey := s.config.ViewPrefix + bucketKey

	bucketEntry := &storageBucketEntry{
		Key: bucketEntryKey,
	}

	// Check if there is an existing bucket for a given key
	storageEntry, err := s.view.Get(bucketEntryKey)
	if err != nil {
		return fmt.Errorf("failed to read packed storage entry: %v", err)
	}

	if storageEntry == nil {
		// If the bucket entry does not exist, this will be only storage entry
		// in a bucket that is going to be persisted.
		bucketEntry.Items = []*entityStorageEntry{
			entity,
		}
	} else {
		// If there already exists a bucket, read it and upsert the new entry
		// to it.
		decompressedBucketEntryBytes, err := snappy.Decode(nil, storageEntry.Value)
		if err != nil {
			return fmt.Errorf("failed to decompress packed storage entry: %v", err)
		}

		err = jsonutil.DecodeJSON(decompressedBucketEntryBytes, bucketEntry)
		if err != nil {
			return fmt.Errorf("failed to decode packed storage entry: %v", err)
		}

		err = bucketEntry.upsert(entity)
		if err != nil {
			return fmt.Errorf("failed to update entry in packed storage entry: %v", err)
		}
	}

	// Persist the result
	return s.Put(bucketEntry)
}

// NewStoragePacker creates a new storage packer for a given configuration and
// view. This will also persist properties of packer which needs to get
// persisted across reboots. If a persisted configuration is found for a given
// location, certain properties which are immutable will be enforced and
// attempts to update it will result in an error.
func NewStoragePacker(view logical.Storage, config *storagePackerConfig, logger log.Logger) (*storagePacker, error) {
	if view == nil {
		return nil, fmt.Errorf("nil view")
	}

	if config == nil {
		config = &storagePackerConfig{}
	}

	if config.Location == "" {
		config.Location = packerConfigLocation
	}

	if config.HashFunc == nil {
		config.HashFunc = md5.New()
	}

	// Currently, only bucket count of 256 is supported
	if config.NumBuckets != bucketCount {
		config.NumBuckets = bucketCount
	}

	// When prefix is not set, assign a default prefix so that all the
	// packed entries are segregated
	if config.ViewPrefix == "" || config.ViewPrefix == "/" {
		config.ViewPrefix = "storagepacker/"
	}

	// If prefix is supplied and it doesn't contain a '/', append it
	if !strings.HasSuffix(config.ViewPrefix, "/") {
		config.ViewPrefix += "/"
	}

	// Create a new packer object for the given config and view
	packer := &storagePacker{
		config: config,
		view:   view,
		logger: logger,
	}

	// Check if there was a configuration which was persisted earlier in the
	// given view.
	entry, err := view.Get(config.Location)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage packer properties: %v", err)
	}

	var configEntry configStorageEntry
	// If yes, restore the configuration properties from it
	if entry != nil {
		err = entry.DecodeJSON(&configEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to decode storage packer properties:%v", err)
		}

		// ViewPrefix is immutable
		if config.ViewPrefix != configEntry.ViewPrefix {
			return nil, fmt.Errorf("existing view prefix %q can't be modified; new value being attempted is %q", configEntry.ViewPrefix, config.ViewPrefix)
		}

		// NumBuckets is immutable
		if config.NumBuckets != configEntry.NumBuckets {
			return nil, fmt.Errorf("existing num_buckets value of %q can't be modified; new value being attempted is %q", configEntry.NumBuckets, config.NumBuckets)
		}

		// Override the config values with the ones that were persisted
		packer.config.NumBuckets = configEntry.NumBuckets
		packer.config.ViewPrefix = configEntry.ViewPrefix
	}

	return packer, nil
}

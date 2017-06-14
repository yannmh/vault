package storageutil

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestStorageUtil(t *testing.T) {
	storagePacker, err := NewStoragePacker(&logical.InmemStorage{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Persist a storage entry
	entry1 := &logical.StorageEntry{
		Key:   "samplekey1",
		Value: []byte("samplevalue1"),
	}

	err = storagePacker.PutItem(entry1)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that it can be read
	fetchedEntry, err := storagePacker.GetItem(entry1.Key)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedEntry == nil {
		t.Fatalf("failed to read the stored entry1")
	}

	if !reflect.DeepEqual(entry1, fetchedEntry) {
		t.Fatalf("bad: mismatching storage entries; expected: %#v\n actual: %#v\n", entry1, fetchedEntry)
	}

	// Persist another storage entry
	entry2 := &logical.StorageEntry{
		Key:   "samplekey2",
		Value: []byte("samplevalue2"),
	}

	err = storagePacker.PutItem(entry2)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that it can be read
	fetchedEntry, err = storagePacker.GetItem(entry2.Key)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedEntry == nil {
		t.Fatalf("failed to read the stored entry2")
	}

	if !reflect.DeepEqual(entry2, fetchedEntry) {
		t.Fatalf("bad: mismatching storage entries; expected: %#v\n actual: %#v\n", entry2, fetchedEntry)
	}

	// Modify the an existing entry
	entry2.Value = []byte("samplenewvalue2")
	err = storagePacker.PutItem(entry2)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the value got updated
	fetchedEntry, err = storagePacker.GetItem(entry2.Key)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedEntry == nil {
		t.Fatalf("failed to read the stored entry2")
	}

	if !reflect.DeepEqual(entry2, fetchedEntry) {
		t.Fatalf("bad: mismatching storage entries; expected: %#v\n actual: %#v\n", entry2, fetchedEntry)
	}

	// Delete entry1
	err = storagePacker.DeleteItem(entry1.Key)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the deletion was successful
	fetchedEntry, err = storagePacker.GetItem(entry1.Key)
	if err != nil {
		t.Fatal(err)
	}

	if fetchedEntry != nil {
		t.Fatalf("failed to delete entry1")
	}

	// Delete entry2
	err = storagePacker.DeleteItem(entry2.Key)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the deletion was successful
	fetchedEntry, err = storagePacker.GetItem(entry2.Key)
	if err != nil {
		t.Fatal(err)
	}

	if fetchedEntry != nil {
		t.Fatalf("failed to delete entry2")
	}
}

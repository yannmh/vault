package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestIdentityStore_StorageUtil(t *testing.T) {
	storagePacker, err := NewStoragePacker(&logical.InmemStorage{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Persist a storage entry
	entity1 := &entityStorageEntry{
		ID:   "entity1",
		Name: "entityname1",
	}

	err = storagePacker.PutItem(entity1)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that it can be read
	fetchedEntry, err := storagePacker.GetItem(entity1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedEntry == nil {
		t.Fatalf("failed to read the stored entity1")
	}

	if !reflect.DeepEqual(entity1, fetchedEntry) {
		t.Fatalf("bad: mismatching storage entries; expected: %#v\n actual: %#v\n", entity1, fetchedEntry)
	}

	// Persist another storage entry
	entity2 := &entityStorageEntry{
		ID:   "entity2",
		Name: "entityname2",
	}

	err = storagePacker.PutItem(entity2)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that it can be read
	fetchedEntry, err = storagePacker.GetItem(entity2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedEntry == nil {
		t.Fatalf("failed to read the stored entity2")
	}

	if !reflect.DeepEqual(entity2, fetchedEntry) {
		t.Fatalf("bad: mismatching storage entries; expected: %#v\n actual: %#v\n", entity2, fetchedEntry)
	}

	// Modify the an existing entry
	entity2.Name = "modifiedentityname2"
	err = storagePacker.PutItem(entity2)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the value got updated
	fetchedEntry, err = storagePacker.GetItem(entity2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedEntry == nil {
		t.Fatalf("failed to read the stored entity2")
	}

	if !reflect.DeepEqual(entity2, fetchedEntry) {
		t.Fatalf("bad: mismatching storage entries; expected: %#v\n actual: %#v\n", entity2, fetchedEntry)
	}

	// Delete entity1
	err = storagePacker.DeleteItem(entity1.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the deletion was successful
	fetchedEntry, err = storagePacker.GetItem(entity1.ID)
	if err != nil {
		t.Fatal(err)
	}

	if fetchedEntry != nil {
		t.Fatalf("failed to delete entity1")
	}

	// Delete entity2
	err = storagePacker.DeleteItem(entity2.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the deletion was successful
	fetchedEntry, err = storagePacker.GetItem(entity2.ID)
	if err != nil {
		t.Fatal(err)
	}

	if fetchedEntry != nil {
		t.Fatalf("failed to delete entity2")
	}
}

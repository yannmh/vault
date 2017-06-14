package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/logical"
)

// This test is required because MemDB does not take care of ensuring
// uniqueness of indexes that are marked unique.
func TestIdentityStore_IdentitySameIdentityNames(t *testing.T) {
	var err error
	var resp *logical.Response
	is := TestIdentityStoreWithGithubAuth(t)

	identityData := map[string]interface{}{
		"name":       "testidentityname",
		"mount_path": "github",
	}

	identityReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "identity",
		Data:      identityData,
	}

	// Register an identity
	resp, err = is.HandleRequest(identityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register another identity with same name
	resp, err = is.HandleRequest(identityReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error due to identity name not being unique")
	}
}

func TestIdentityStore_MemDBIdentityIndexes(t *testing.T) {
	var err error

	is := TestIdentityStoreWithGithubAuth(t)
	if is == nil {
		t.Fatal("failed to create test identity store")
	}

	validateMountResp := is.validateMountPathFunc("github")
	if validateMountResp == nil {
		t.Fatal("failed to validate github auth mount")
	}

	entity := &entityStorageEntry{
		ID:   "testentityid",
		Name: "testentityname",
	}

	err = is.memDBUpsertEntity(entity)
	if err != nil {
		t.Fatal(err)
	}

	identity := &identityIndexEntry{
		EntityID:  entity.ID,
		ID:        "testidentityid",
		MountID:   validateMountResp.MountID,
		MountType: validateMountResp.MountType,
		Name:      "testidentityname",
		Metadata: map[string]string{
			"testkey1": "testmetadatavalue1",
			"testkey2": "testmetadatavalue2",
		},
	}

	err = is.memDBUpsertIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}

	identityFetched, err := is.memDBIdentityByID("testidentityid")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(identity, identityFetched) {
		t.Fatalf("bad: mismatched identities; expected: %#v\n actual: %#v\n", identity, identityFetched)
	}

	identityFetched, err = is.memDBIdentityByEntityID(entity.ID)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(identity, identityFetched) {
		t.Fatalf("bad: mismatched identities; expected: %#v\n actual: %#v\n", identity, identityFetched)
	}

	identityFetched, err = is.memDBIdentityByFactors(validateMountResp.MountID, "testidentityname")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(identity, identityFetched) {
		t.Fatalf("bad: mismatched identities; expected: %#v\n actual: %#v\n", identity, identityFetched)
	}

	identitiesFetched, err := is.memDBIdentitiesByMetadata(map[string]string{
		"testkey1": "testmetadatavalue1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(identitiesFetched) != 1 {
		t.Fatalf("bad: length of identities; expected: 1, actual: %d", len(identitiesFetched))
	}

	if !reflect.DeepEqual(identity, identitiesFetched[0]) {
		t.Fatalf("bad: mismatched identities; expected: %#v\n actual: %#v\n", identity, identityFetched)
	}

	identitiesFetched, err = is.memDBIdentitiesByMetadata(map[string]string{
		"testkey2": "testmetadatavalue2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(identitiesFetched) != 1 {
		t.Fatalf("bad: length of identities; expected: 1, actual: %d", len(identitiesFetched))
	}

	if !reflect.DeepEqual(identity, identitiesFetched[0]) {
		t.Fatalf("bad: mismatched identities; expected: %#v\n actual: %#v\n", identity, identityFetched)
	}

	identitiesFetched, err = is.memDBIdentitiesByMetadata(map[string]string{
		"testkey1": "testmetadatavalue1",
		"testkey2": "testmetadatavalue2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(identitiesFetched) != 1 {
		t.Fatalf("bad: length of identities; expected: 1, actual: %d", len(identitiesFetched))
	}

	if !reflect.DeepEqual(identity, identitiesFetched[0]) {
		t.Fatalf("bad: mismatched identities; expected: %#v\n actual: %#v\n", identity, identityFetched)
	}

	identity2 := &identityIndexEntry{
		EntityID:  entity.ID,
		ID:        "testidentityid2",
		MountID:   validateMountResp.MountID,
		MountType: validateMountResp.MountType,
		Name:      "testidentityname2",
		Metadata: map[string]string{
			"testkey1": "testmetadatavalue1",
			"testkey3": "testmetadatavalue3",
		},
	}

	err = is.memDBUpsertIdentity(identity2)
	if err != nil {
		t.Fatal(err)
	}

	identitiesFetched, err = is.memDBIdentitiesByMetadata(map[string]string{
		"testkey1": "testmetadatavalue1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(identitiesFetched) != 2 {
		t.Fatalf("bad: length of identities; expected: 2, actual: %d", len(identitiesFetched))
	}

	identitiesFetched, err = is.memDBIdentitiesByMetadata(map[string]string{
		"testkey3": "testmetadatavalue3",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(identitiesFetched) != 1 {
		t.Fatalf("bad: length of identities; expected: 1, actual: %d", len(identitiesFetched))
	}

	err = is.memDBDeleteIdentityByID("testidentityid")
	if err != nil {
		t.Fatal(err)
	}

	identityFetched, err = is.memDBIdentityByID("testidentityid")
	if err != nil {
		t.Fatal(err)
	}

	if identityFetched != nil {
		t.Fatalf("expected a nil identity")
	}
}

func TestIdentityStore_IdentityRegister(t *testing.T) {
	var err error
	var resp *logical.Response

	is := TestIdentityStoreWithGithubAuth(t)
	if is == nil {
		t.Fatal("failed to create test identity store")
	}

	identityData := map[string]interface{}{
		"name":       "testidentityname",
		"mount_path": "github",
		"metadata": map[string]string{
			"organization": "hashicorp",
			"team":         "vault",
		},
	}

	identityReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "identity",
		Data:      identityData,
	}

	// Register the identity
	resp, err = is.HandleRequest(identityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("identity id not present in identity register response")
	}

	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid identity id in identity register response")
	}

	entityIDRaw, ok := resp.Data["entity_id"]
	if !ok {
		t.Fatalf("entity id not present in identity register response")
	}

	entityID := entityIDRaw.(string)
	if entityID == "" {
		t.Fatalf("invalid entity id in identity register response")
	}
}

func TestIdentityStore_IdentityUpdate(t *testing.T) {
	var err error
	var resp *logical.Response
	is := TestIdentityStoreWithGithubAuth(t)

	updateData := map[string]interface{}{
		"name":       "updatedidentityname",
		"mount_path": "github",
		"metadata": map[string]string{
			"organization": "updatedorganization",
			"team":         "updatedteam",
		},
	}

	updateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "identity/id/invalididentityid",
		Data:      updateData,
	}

	// Try to update an non-existent identity
	resp, err = is.HandleRequest(updateReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error due to invalid identity id")
	}

	registerData := map[string]interface{}{
		"name":       "testidentityname",
		"mount_path": "github",
		"metadata": map[string]string{
			"organization": "hashicorp",
			"team":         "vault",
		},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "identity",
		Data:      registerData,
	}

	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("identity id not present in response")
	}
	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid identity id")
	}

	updateReq.Path = "identity/id/" + id
	resp, err = is.HandleRequest(updateReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      updateReq.Path,
	}
	resp, err = is.HandleRequest(readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	identityMetadata := resp.Data["metadata"].(map[string]string)
	updatedOrg := identityMetadata["organization"]
	updatedTeam := identityMetadata["team"]

	if resp.Data["name"] != "updatedidentityname" || updatedOrg != "updatedorganization" || updatedTeam != "updatedteam" {
		t.Fatal("failed to update identity information")
	}

	delete(registerReq.Data, "name")

	resp, err = is.HandleRequest(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error due to missing identity name")
	}

	registerReq.Data["name"] = "testidentityname"
	delete(registerReq.Data, "mount_path")

	resp, err = is.HandleRequest(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error due to missing mount path")
	}
}

func TestIdentityStore_IdentityReadDelete(t *testing.T) {
	var err error
	var resp *logical.Response

	is := TestIdentityStoreWithGithubAuth(t)

	registerData := map[string]interface{}{
		"name":       "testidentityname",
		"mount_path": "github",
		"metadata": map[string]string{
			"organization": "hashicorp",
			"team":         "vault",
		},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "identity",
		Data:      registerData,
	}

	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("identity id not present in response")
	}
	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid identity id")
	}

	// Read it back using identity id
	identityReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "identity/id/" + id,
	}
	resp, err = is.HandleRequest(identityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["id"].(string) == "" ||
		resp.Data["entity_id"].(string) == "" ||
		resp.Data["name"].(string) != registerData["name"] ||
		!reflect.DeepEqual(registerData["metadata"], resp.Data["metadata"].(map[string]string)) ||
		resp.Data["mount_type"].(string) != "github" {
		t.Fatal("bad: identity read response: %#v\n", resp)
	}

	_, ok = resp.Data["mount_id"]
	if ok {
		t.Fatal("mount id should never be returned")
	}

	identityReq.Operation = logical.DeleteOperation
	resp, err = is.HandleRequest(identityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	identityReq.Operation = logical.ReadOperation
	resp, err = is.HandleRequest(identityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp != nil {
		t.Fatalf("bad: identity read response; expected: nil, actual: %#v\n", resp)
	}
}

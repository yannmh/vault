package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/logical"
)

// This test is required because MemDB does not take care of ensuring
// uniqueness of indexes that are marked unique.
func TestIdentityStore_PersonaSamePersonaNames(t *testing.T) {
	var err error
	var resp *logical.Response
	is := TestIdentityStoreWithGithubAuth(t)

	personaData := map[string]interface{}{
		"name":       "testpersonaname",
		"mount_path": "github",
	}

	personaReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "persona",
		Data:      personaData,
	}

	// Register a persona
	resp, err = is.HandleRequest(personaReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register another persona with same name
	resp, err = is.HandleRequest(personaReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error due to persona name not being unique")
	}
}

func TestIdentityStore_MemDBPersonaIndexes(t *testing.T) {
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

	persona := &personaIndexEntry{
		EntityID:  entity.ID,
		ID:        "testpersonaid",
		MountID:   validateMountResp.MountID,
		MountType: validateMountResp.MountType,
		Name:      "testpersonaname",
		Metadata: map[string]string{
			"testkey1": "testmetadatavalue1",
			"testkey2": "testmetadatavalue2",
		},
	}

	err = is.memDBUpsertPersona(persona)
	if err != nil {
		t.Fatal(err)
	}

	personaFetched, err := is.memDBPersonaByID("testpersonaid")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(persona, personaFetched) {
		t.Fatalf("bad: mismatched personas; expected: %#v\n actual: %#v\n", persona, personaFetched)
	}

	personaFetched, err = is.memDBPersonaByEntityID(entity.ID)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(persona, personaFetched) {
		t.Fatalf("bad: mismatched personas; expected: %#v\n actual: %#v\n", persona, personaFetched)
	}

	personaFetched, err = is.memDBPersonaByFactors(validateMountResp.MountID, "testpersonaname")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(persona, personaFetched) {
		t.Fatalf("bad: mismatched personas; expected: %#v\n actual: %#v\n", persona, personaFetched)
	}

	personasFetched, err := is.memDBPersonasByMetadata(map[string]string{
		"testkey1": "testmetadatavalue1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(personasFetched) != 1 {
		t.Fatalf("bad: length of personas; expected: 1, actual: %d", len(personasFetched))
	}

	if !reflect.DeepEqual(persona, personasFetched[0]) {
		t.Fatalf("bad: mismatched personas; expected: %#v\n actual: %#v\n", persona, personaFetched)
	}

	personasFetched, err = is.memDBPersonasByMetadata(map[string]string{
		"testkey2": "testmetadatavalue2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(personasFetched) != 1 {
		t.Fatalf("bad: length of personas; expected: 1, actual: %d", len(personasFetched))
	}

	if !reflect.DeepEqual(persona, personasFetched[0]) {
		t.Fatalf("bad: mismatched personas; expected: %#v\n actual: %#v\n", persona, personaFetched)
	}

	personasFetched, err = is.memDBPersonasByMetadata(map[string]string{
		"testkey1": "testmetadatavalue1",
		"testkey2": "testmetadatavalue2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(personasFetched) != 1 {
		t.Fatalf("bad: length of personas; expected: 1, actual: %d", len(personasFetched))
	}

	if !reflect.DeepEqual(persona, personasFetched[0]) {
		t.Fatalf("bad: mismatched personas; expected: %#v\n actual: %#v\n", persona, personaFetched)
	}

	persona2 := &personaIndexEntry{
		EntityID:  entity.ID,
		ID:        "testpersonaid2",
		MountID:   validateMountResp.MountID,
		MountType: validateMountResp.MountType,
		Name:      "testpersonaname2",
		Metadata: map[string]string{
			"testkey1": "testmetadatavalue1",
			"testkey3": "testmetadatavalue3",
		},
	}

	err = is.memDBUpsertPersona(persona2)
	if err != nil {
		t.Fatal(err)
	}

	personasFetched, err = is.memDBPersonasByMetadata(map[string]string{
		"testkey1": "testmetadatavalue1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(personasFetched) != 2 {
		t.Fatalf("bad: length of personas; expected: 2, actual: %d", len(personasFetched))
	}

	personasFetched, err = is.memDBPersonasByMetadata(map[string]string{
		"testkey3": "testmetadatavalue3",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(personasFetched) != 1 {
		t.Fatalf("bad: length of personas; expected: 1, actual: %d", len(personasFetched))
	}

	err = is.memDBDeletePersonaByID("testpersonaid")
	if err != nil {
		t.Fatal(err)
	}

	personaFetched, err = is.memDBPersonaByID("testpersonaid")
	if err != nil {
		t.Fatal(err)
	}

	if personaFetched != nil {
		t.Fatalf("expected a nil persona")
	}
}

func TestIdentityStore_IdentityRegister(t *testing.T) {
	var err error
	var resp *logical.Response

	is := TestIdentityStoreWithGithubAuth(t)
	if is == nil {
		t.Fatal("failed to create test persona store")
	}

	personaData := map[string]interface{}{
		"name":       "testpersonaname",
		"mount_path": "github",
		"metadata":   []string{"organization:hashicorp", "team:vault"},
	}

	personaReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "persona",
		Data:      personaData,
	}

	// Register the persona
	resp, err = is.HandleRequest(personaReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("persona id not present in persona register response")
	}

	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid persona id in persona register response")
	}

	entityIDRaw, ok := resp.Data["entity_id"]
	if !ok {
		t.Fatalf("entity id not present in persona register response")
	}

	entityID := entityIDRaw.(string)
	if entityID == "" {
		t.Fatalf("invalid entity id in persona register response")
	}
}

func TestIdentityStore_PersonaUpdate(t *testing.T) {
	var err error
	var resp *logical.Response
	is := TestIdentityStoreWithGithubAuth(t)

	updateData := map[string]interface{}{
		"name":       "updatedpersonaname",
		"mount_path": "github",
		"metadata":   []string{"organization:updatedorganization", "team:updatedteam"},
	}

	updateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "persona/id/invalidpersonaid",
		Data:      updateData,
	}

	// Try to update an non-existent persona
	resp, err = is.HandleRequest(updateReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error due to invalid persona id")
	}

	registerData := map[string]interface{}{
		"name":       "testpersonaname",
		"mount_path": "github",
		"metadata":   []string{"organization:hashicorp", "team:vault"},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "persona",
		Data:      registerData,
	}

	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("persona id not present in response")
	}
	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid persona id")
	}

	updateReq.Path = "persona/id/" + id
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

	personaMetadata := resp.Data["metadata"].(map[string]string)
	updatedOrg := personaMetadata["organization"]
	updatedTeam := personaMetadata["team"]

	if resp.Data["name"] != "updatedpersonaname" || updatedOrg != "updatedorganization" || updatedTeam != "updatedteam" {
		t.Fatalf("failed to update persona information; \n response data: %#v\n", resp.Data)
	}

	delete(registerReq.Data, "name")

	resp, err = is.HandleRequest(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error due to missing persona name")
	}

	registerReq.Data["name"] = "testpersonaname"
	delete(registerReq.Data, "mount_path")

	resp, err = is.HandleRequest(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error due to missing mount path")
	}
}

func TestIdentityStore_PersonaReadDelete(t *testing.T) {
	var err error
	var resp *logical.Response

	is := TestIdentityStoreWithGithubAuth(t)

	registerData := map[string]interface{}{
		"name":       "testpersonaname",
		"mount_path": "github",
		"metadata":   []string{"organization:hashicorp", "team:vault"},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "persona",
		Data:      registerData,
	}

	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("persona id not present in response")
	}
	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid persona id")
	}

	// Read it back using persona id
	personaReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "persona/id/" + id,
	}
	resp, err = is.HandleRequest(personaReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["id"].(string) == "" ||
		resp.Data["entity_id"].(string) == "" ||
		resp.Data["name"].(string) != registerData["name"] ||
		resp.Data["mount_type"].(string) != "github" {
		t.Fatalf("bad: persona read response; \nexpected: %#v \nactual: %#v\n", registerData, resp.Data)
	}

	_, ok = resp.Data["mount_id"]
	if ok {
		t.Fatal("mount id should never be returned")
	}

	personaReq.Operation = logical.DeleteOperation
	resp, err = is.HandleRequest(personaReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	personaReq.Operation = logical.ReadOperation
	resp, err = is.HandleRequest(personaReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp != nil {
		t.Fatalf("bad: persona read response; expected: nil, actual: %#v\n", resp)
	}
}

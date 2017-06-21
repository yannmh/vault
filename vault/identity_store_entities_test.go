package vault

import (
	"reflect"
	"testing"

	uuid "github.com/hashicorp/go-uuid"
	credGithub "github.com/hashicorp/vault/builtin/credential/github"
	"github.com/hashicorp/vault/logical"
)

func TestIdentityStore_RestoringEntities(t *testing.T) {
	var resp *logical.Response
	// Add github credential factory to core config
	err := AddTestCredentialBackend("github", credGithub.Factory)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	c := TestCore(t)
	unsealKeys, token := TestCoreInit(t, c)
	for _, key := range unsealKeys {
		if _, err := TestCoreUnseal(c, TestKeyCopy(key)); err != nil {
			t.Fatalf("unseal err: %s", err)
		}
	}

	sealed, err := c.Sealed()
	if err != nil {
		t.Fatalf("err checking seal status: %s", err)
	}
	if sealed {
		t.Fatal("should not be sealed")
	}

	meGH := &MountEntry{
		Table:       credentialTableType,
		Path:        "github/",
		Type:        "github",
		Description: "github auth",
	}

	// Mount UUID for github auth
	meGHUUID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	meGH.UUID = meGHUUID

	// Storage view for github auth
	ghView := NewBarrierView(c.barrier, credentialBarrierPrefix+meGH.UUID+"/")

	// Sysview for github auth
	ghSysview := c.mountEntrySysView(meGH)

	// Create new github auth credential backend
	ghAuth, err := c.newCredentialBackend(meGH.Type, ghSysview, ghView, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mount github auth
	err = c.router.Mount(ghAuth, "auth/github", meGH, ghView)
	if err != nil {
		t.Fatal(err)
	}

	// Identity store will be mounted by now, just fetch it from router
	identitystore := c.router.MatchingBackend("identity/")
	if identitystore == nil {
		t.Fatalf("failed to fetch identity store from router")
	}

	is := identitystore.(*identityStore)

	registerData := map[string]interface{}{
		"name":     "testentityname",
		"metadata": []string{"someusefulkey:someusefulvalue"},
		"identities": []interface{}{
			map[string]interface{}{
				"name":       "testidentityname1",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
			map[string]interface{}{
				"name":       "testidentityname2",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
		},
		"policies": []string{"testpolicy1", "testpolicy2"},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity",
		Data:      registerData,
	}

	// Register the entity
	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	entityID := resp.Data["id"].(string)

	readReq := &logical.Request{
		Path:      "entity/id/" + entityID,
		Operation: logical.ReadOperation,
	}

	// Ensure that entity is created
	resp, err = is.HandleRequest(readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["id"] != entityID {
		t.Fatalf("failed to read the created entity")
	}

	// Perform a seal/unseal cycle
	err = c.Seal(token)
	if err != nil {
		t.Fatalf("failed to seal core: %v", err)
	}

	sealed, err = c.Sealed()
	if err != nil {
		t.Fatalf("err checking seal status: %s", err)
	}
	if !sealed {
		t.Fatal("should be sealed")
	}

	for _, key := range unsealKeys {
		if _, err := TestCoreUnseal(c, TestKeyCopy(key)); err != nil {
			t.Fatalf("unseal err: %s", err)
		}
	}

	sealed, err = c.Sealed()
	if err != nil {
		t.Fatalf("err checking seal status: %s", err)
	}
	if sealed {
		t.Fatal("should not be sealed")
	}

	// Check if the entity is restored
	resp, err = is.HandleRequest(readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["id"] != entityID {
		t.Fatalf("failed to read the created entity after a seal/unseal cycle")
	}
}

func TestIdentityStore_MemDBEntityIndexes(t *testing.T) {
	var err error

	is := TestIdentityStoreWithGithubAuth(t)

	validateMountResp := is.validateMountPathFunc("github")
	if validateMountResp == nil {
		t.Fatal("failed to validate github auth mount")
	}

	identity1 := &identityIndexEntry{
		EntityID:  "testentityid",
		ID:        "testidentityid",
		MountID:   validateMountResp.MountID,
		MountType: validateMountResp.MountType,
		Name:      "testidentityname",
		Metadata: map[string]string{
			"testkey1": "testmetadatavalue1",
			"testkey2": "testmetadatavalue2",
		},
	}

	identity2 := &identityIndexEntry{
		EntityID:  "testentityid",
		ID:        "testidentityid2",
		MountID:   validateMountResp.MountID,
		MountType: validateMountResp.MountType,
		Name:      "testidentityname2",
		Metadata: map[string]string{
			"testkey2": "testmetadatavalue2",
			"testkey3": "testmetadatavalue3",
		},
	}

	entity := &entityStorageEntry{
		ID:   "testentityid",
		Name: "testentityname",
		Metadata: map[string]string{
			"someusefulkey": "someusefulvalue",
		},
		Identities: []*identityIndexEntry{
			identity1,
			identity2,
		},
	}

	err = is.memDBUpsertEntity(entity)
	if err != nil {
		t.Fatal(err)
	}

	entityFetched, err := is.memDBEntityByID(entity.ID)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(entity, entityFetched) {
		t.Fatalf("bad: mismatched entities; expected: %#v\n actual: %#v\n", entity, entityFetched)
	}

	entityFetched, err = is.memDBEntityByName(entity.Name)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(entity, entityFetched) {
		t.Fatalf("entity mismatched entities; expected: %#v\n actual: %#v\n", entity, entityFetched)
	}

	entitiesFetched, err := is.memDBEntitiesByMetadata(map[string]string{
		"someusefulkey": "someusefulvalue",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(entitiesFetched) != 1 {
		t.Fatalf("bad: length of entities; expected: 1, actual: %d", len(entitiesFetched))
	}

	if !reflect.DeepEqual(entity, entitiesFetched[0]) {
		t.Fatalf("entity mismatch; entity2: %#v\n entitiesFetched[0]: %#v\n", entity, entitiesFetched[0])
	}

	err = is.memDBDeleteEntityByID(entity.ID)
	if err != nil {
		t.Fatal(err)
	}

	entityFetched, err = is.memDBEntityByID(entity.ID)
	if err != nil {
		t.Fatal(err)
	}

	if entityFetched != nil {
		t.Fatal("bad: entity; expected: nil, actual: %#v\n", entityFetched)
	}

	entityFetched, err = is.memDBEntityByName(entity.Name)
	if err != nil {
		t.Fatal(err)
	}

	if entityFetched != nil {
		t.Fatal("bad: entity; expected: nil, actual: %#v\n", entityFetched)
	}
}

// This test is required because MemDB does not take care of ensuring
// uniqueness of indexes that are marked unique. It is the job of the higher
// level abstraction, the identity store in this case.
func TestIdentityStore_EntitySameEntityNames(t *testing.T) {
	var err error
	var resp *logical.Response
	is := TestIdentityStoreWithGithubAuth(t)

	registerData := map[string]interface{}{
		"name": "testentityname",
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity",
		Data:      registerData,
	}

	// Register an entity
	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register another entity with same name
	resp, err = is.HandleRequest(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error due to entity name not being unique")
	}
}

func TestIdentityStore_EntityCRUD(t *testing.T) {
	var err error
	var resp *logical.Response

	is := TestIdentityStoreWithGithubAuth(t)

	registerData := map[string]interface{}{
		"name":     "testentityname",
		"metadata": []string{"someusefulkey:someusefulvalue"},
		"identities": []interface{}{
			map[string]interface{}{
				"name":       "testidentityname1",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
			map[string]interface{}{
				"name":       "testidentityname2",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
		},
		"policies": []string{"testpolicy1", "testpolicy2"},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity",
		Data:      registerData,
	}

	// Register the entity
	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	idRaw, ok := resp.Data["id"]
	if !ok {
		t.Fatalf("entity id not present in response")
	}
	id := idRaw.(string)
	if id == "" {
		t.Fatalf("invalid entity id")
	}

	identitiesRaw, ok := resp.Data["identities"]
	if !ok {
		t.Fatalf("identities missing in entity registration response")
	}
	identities := identitiesRaw.([]string)

	if len(identities) != 2 {
		t.Fatalf("bad: number of identities in entity registration response; expected: 2, actual: %d", len(identities))
	}

	readReq := &logical.Request{
		Path:      "entity/id/" + id,
		Operation: logical.ReadOperation,
	}

	resp, err = is.HandleRequest(readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["id"] != id ||
		resp.Data["name"] != registerData["name"] ||
		len(resp.Data["identities"].([]interface{})) != 2 ||
		!reflect.DeepEqual(resp.Data["policies"], registerData["policies"]) {
		t.Fatalf("bad: entity response")
	}

	updateData := map[string]interface{}{
		"name":     "updatedentityname",
		"metadata": []string{"updatedkey:updatedvalue"},
		"identities": []interface{}{
			map[string]interface{}{
				"name":       "updatedidentityname",
				"mount_path": "github",
				"metadata":   []string{"updatedidentitymetakey:updatedidentitymetavalue"},
			},
		},
		"policies": []string{"updatedpolicy1", "updatedpolicy2"},
	}

	updateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity/id/" + id,
		Data:      updateData,
	}

	resp, err = is.HandleRequest(updateReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	resp, err = is.HandleRequest(readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["id"] != id ||
		resp.Data["name"] != updateData["name"] ||
		len(resp.Data["identities"].([]interface{})) != 1 ||
		!reflect.DeepEqual(resp.Data["policies"], updateData["policies"]) {
		t.Fatalf("bad: entity response after update; resp: %#v\n updateData: %#v\n", resp.Data, updateData)
	}

	deleteReq := &logical.Request{
		Path:      "entity/id/" + id,
		Operation: logical.DeleteOperation,
	}

	resp, err = is.HandleRequest(deleteReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	resp, err = is.HandleRequest(readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp != nil {
		t.Fatalf("expected a nil response; actual: %#v\n", resp)
	}
}

func TestIdentityStore_MergeEntitiesByID(t *testing.T) {
	var err error
	var resp *logical.Response

	is := TestIdentityStoreWithGithubAuth(t)

	registerData := map[string]interface{}{
		"name":     "testentityname2",
		"metadata": []string{"someusefulkey:someusefulvalue"},
		"identities": []interface{}{
			map[string]interface{}{
				"name":       "testidentityname1",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
			map[string]interface{}{
				"name":       "testidentityname2",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
		},
	}

	registerData2 := map[string]interface{}{
		"name":     "testentityname",
		"metadata": []string{"someusefulkey:someusefulvalue"},
		"identities": []interface{}{
			map[string]interface{}{
				"name":       "testidentityname3",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
			map[string]interface{}{
				"name":       "testidentityname4",
				"mount_path": "github",
				"metadata":   []string{"organization:hashicorp", "team:vault"},
			},
		},
	}

	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity",
		Data:      registerData,
	}

	// Register the entity
	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	entityID1 := resp.Data["id"].(string)

	entity1, err := is.memDBEntityByID(entityID1)
	if err != nil {
		t.Fatal(err)
	}
	if entity1 == nil {
		t.Fatalf("failed to create entity: %v", err)
	}

	identities1 := resp.Data["identities"].([]string)
	if len(identities1) != 2 {
		t.Fatalf("bad: number of identities in entity; expected: 2, actual: %d", len(identities1))
	}

	for _, identityID := range identities1 {
		identity, err := is.memDBIdentityByID(identityID)
		if err != nil {
			t.Fatal(err)
		}
		if identity == nil {
			t.Fatalf("identity of the entity is not indexed")
		}
	}

	registerReq.Data = registerData2
	// Register another entity
	resp, err = is.HandleRequest(registerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	entityID2 := resp.Data["id"].(string)

	entity2, err := is.memDBEntityByID(entityID2)
	if err != nil {
		t.Fatal(err)
	}
	if entity2 == nil {
		t.Fatalf("failed to create entity: %v", err)
	}

	identities2 := resp.Data["identities"].([]string)
	if len(identities2) != 2 {
		t.Fatalf("bad: number of identities in entity; expected: 2, actual: %d", len(identities2))
	}

	for _, identityID := range identities2 {
		identity, err := is.memDBIdentityByID(identityID)
		if err != nil {
			t.Fatal(err)
		}
		if identity == nil {
			t.Fatalf("identity of the entity is not indexed")
		}
	}

	mergeData := map[string]interface{}{
		"to_entity_id":    entityID1,
		"from_entity_ids": []string{entityID2},
	}
	mergeReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity/merge/id",
		Data:      mergeData,
	}

	resp, err = is.HandleRequest(mergeReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	entityReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "entity/id/" + entityID2,
	}
	resp, err = is.HandleRequest(entityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp != nil {
		t.Fatalf("entity should have been deleted")
	}

	entityReq.Path = "entity/id/" + entityID1
	resp, err = is.HandleRequest(entityReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	ghMountTypeCount := 0
	aliasMountTypeCount := 0
	entity2Identities := resp.Data["identities"].([]interface{})
	if len(entity2Identities) != 4 {
		t.Fatalf("bad: number of identities in entity; expected: 4, actual: %d", len(entity2Identities))
	}

	for _, identityRaw := range entity2Identities {
		identity := identityRaw.(map[string]interface{})
		mountType := identity["mount_type"].(string)
		switch mountType {
		case "github":
			ghMountTypeCount++
		case "EntityAlias":
			aliasMountTypeCount++
		default:
			t.Fatalf("invalid mount type: %q", mountType)
		}

		identityID := identity["id"].(string)
		identityLookedUp, err := is.memDBIdentityByID(identityID)
		if err != nil {
			t.Fatal(err)
		}
		if identityLookedUp == nil {
			t.Fatalf("index for identity id %q is not updated", identityID)
		}
	}

	if ghMountTypeCount != 2 {
		t.Fatalf("incorrect number of identities with mount_type github; expected: 2, actual: %d", ghMountTypeCount)
	}

	if aliasMountTypeCount != 2 {
		t.Fatalf("incorrect number of identities with mount_type EntityAlias; expected: 2, actual: %d", aliasMountTypeCount)
	}
}

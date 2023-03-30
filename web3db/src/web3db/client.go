package web3db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"
	"web3db/src/common"
	client "web3db/src/threaddb"

	"github.com/alecthomas/jsonschema"
	threadDB "github.com/textileio/go-threads/api/client"
	"github.com/textileio/go-threads/core/thread"
	db "github.com/textileio/go-threads/db"
)

type Web3DBClient struct {
	selfId           thread.Identity
	selfThreadDbAddr string
	ThreadDBAddr     string
	identity         string // client a.identity
	networkMetadata  thread.ID
}

func NewClient(identity string, selfThreadDbAddr string, selfIdentity thread.Identity, networkMetadata thread.ID) Web3DBClient {
	self := Web3DBClient{selfThreadDbAddr: selfThreadDbAddr, selfId: selfIdentity, identity: identity, networkMetadata: networkMetadata}
	self.findPeerToResolveRequest()
	return self
}

func (a *Web3DBClient) ClaimThread(encryptedThreadClaimToken string, threadId thread.ID) error {
	client, err := client.New(a.selfThreadDbAddr, a.selfId)
	a.ThreadDBAddr = a.selfThreadDbAddr
	if err != nil {
		log.Printf("Error creating ThreadDB client: %s", err)
		return errors.New("Internal Server Error")
	}
	bytes, err := common.ECCDecrypt(a.selfId, encryptedThreadClaimToken)
	if err != nil {
		return fmt.Errorf("Thread Claim Failure: %s", err)
	}
	threadClaimToken := base64.StdEncoding.EncodeToString(bytes)

	res, err := client.Db.Find(context.Background(),
		a.networkMetadata,
		common.ThreadPurchaseInfoSchemaName,
		db.Where("_id").Eq(threadId),
		&common.ThreadPurchasesSchema{})

	if res == nil {
		return fmt.Errorf("Thread %s not for sale", threadId)
	}
	candidates := res.([]*common.ThreadPurchasesSchema)
	if len(candidates) == 0 {
		return fmt.Errorf("Thread %s not for sale", threadId)
	}
	candidate := candidates[0]
	if candidate.ThreadClaimToken != threadClaimToken {
		return fmt.Errorf("Invalid Thread Claim Token")
	}

	// successful purchase
	deleteMe := make([]string, 1)
	deleteMe = append(deleteMe, candidate.Id)
	err = client.Db.Delete(context.Background(), a.networkMetadata, common.ThreadPurchaseInfoSchemaName, deleteMe)
	if err != nil {
		log.Printf("Error removing ThreadPurchaseSchema entry")
	}
	err = client.Db.Delete(context.Background(), a.networkMetadata, common.ThreadsForSaleSchemaName, deleteMe)
	err = client.Db.Delete(context.Background(), a.networkMetadata, common.ThreadPurchaseInfoSchemaName, deleteMe)
	if err != nil {
		log.Printf("Error removing ThreadPurchaseInfoSchemaName entry")
	}
	res, err = client.Db.Find(context.Background(), a.networkMetadata, fmt.Sprintf("ThreadAcl-%s", threadId.String()), db.Where("pubKey").Eq(a.identity), &common.ThreadAclSchema{})
	if err != nil {
		log.Printf("Error Querying %s", fmt.Sprintf("ThreadAcl-%s", threadId.String()))
	}

	if res == nil || len(res.([]*common.ThreadAclSchema)) == 0 {
		// create entry
		owner := common.ThreadAclSchema{
			PubKey:     common.PubKey(a.identity),
			Permission: common.Admin,
		}
		_, err := client.Db.Create(context.Background(), a.networkMetadata, fmt.Sprintf("ThreadAcl-%s", threadId.String()), threadDB.Instances{owner})
		if err != nil {
			log.Printf("Error creating entry for %s in %s collection", a.identity, fmt.Sprintf("ThreadAcl-%s", threadId.String()))
			return fmt.Errorf("Error transferring thread ownership")
		}

	} else {
		// entry exists
		entry := res.([]*common.ThreadAclSchema)[0]
		entry.Permission = common.Admin
		err := client.Db.Save(context.Background(), a.networkMetadata, fmt.Sprintf("ThreadAcl-%s", threadId.String()), threadDB.Instances{entry})
		if err != nil {
			log.Printf("Error updating entry for %s in %s collection", a.identity, fmt.Sprintf("ThreadAcl-%s", threadId.String()))
			return fmt.Errorf("Error transferring thread ownership")
		}
	}
	return nil
}
func (a *Web3DBClient) findPeerToResolveRequest() {
	client, err := client.New(a.selfThreadDbAddr, a.selfId)
	a.ThreadDBAddr = a.selfThreadDbAddr
	if err != nil {
		log.Printf("Error creating ThreadDB client: %s", err)
		return
	}
	res, err := client.Db.Find(context.Background(), a.networkMetadata, common.NodeQueueSchemaName, &db.Query{}, &common.NodeQueueSchema{})
	if err != nil || res == nil {
		log.Printf("Error querying NodeQueue: %s", err)
		return
	}
	candidates := res.([]*common.NodeQueueSchema)
	if len(candidates) == 0 {
		return
	}
	// arbitrarily choose a peer in the NodeQueue
	rand.Seed(time.Now().Unix())
	candidate := candidates[rand.Intn(len(candidates))]
	a.ThreadDBAddr = common.IpAddrFromMultiAddr(candidate.MultiAddr) + ":" + strconv.Itoa(candidate.ThreadDbPort)
}

func (a *Web3DBClient) PublicKey() string {
	return a.selfId.GetPublic().String()
}

func (a *Web3DBClient) NewDB(params common.NewDBParams) (thread.ID, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return "", err
	}
	threadId := thread.NewIDV1(thread.Raw, 32)
	err = client.Db.NewDB(context.Background(), threadId, db.WithNewManagedName(params.Name))
	// add DB info to ThreadInNetwork
	log.Printf("Created thread %s\n", threadId.String())
	if err != nil {
		client.Db.Close()
		log.Printf("Error with DB creation: %s\n", err.Error())
		return "", err
	}
	reflector := jsonschema.Reflector{}
	// create collection level acl data
	collectionAclSchema := reflector.Reflect(&common.CollectionAclSchema{})
	collectionName := fmt.Sprintf("CollectionsAcl-%s", threadId.String())
	err = client.Db.NewCollection(context.Background(), threadId, db.CollectionConfig{
		Name:   collectionName,
		Schema: collectionAclSchema,
	})
	if err != nil {
		client.Db.Close()
		log.Printf("Error creating collection acl collection: %s\n", err.Error())
		return "", err
	}
	// create thread level acl data
	threadAclSchema := reflector.Reflect(common.ThreadAclSchema{})
	collectionName = fmt.Sprintf("ThreadAcl-%s", threadId.String())
	err = client.Db.NewCollection(context.Background(), threadId, db.CollectionConfig{
		Name:   collectionName,
		Schema: threadAclSchema,
	})
	if err != nil {
		client.Db.Close()
		log.Printf("Error creating thread acl collection: %s\n", err.Error())
		return "", err
	}
	var instances threadDB.Instances
	for _, entry := range params.Acl {
		aclEntry := common.ThreadAclSchema{
			ID:         "",
			PubKey:     common.PubKey(entry.PubKey),
			Permission: common.Permissions(entry.Permission),
		}
		instances = append(instances, aclEntry)
	}
	// add creator as admin to acl
	instances = append(instances, common.ThreadAclSchema{
		ID:         "",
		Permission: common.Admin,
		PubKey:     common.PubKey(a.identity),
	})
	_, err = client.Db.Create(context.Background(), threadId, collectionName, instances)
	if err != nil {
		log.Printf("Error Creating thread acl schema instances: %s\n", err.Error())
		return "", err
	}
	dbInfo, err := client.Db.GetDBInfo(context.Background(), threadId)
	if err != nil {
		log.Printf("Error retrieving DBInfo for %s: %s\n", threadId, err.Error())
		return "", err
	}
	threadInNetwork := common.ThreadsInNetworkSchema{
		Id:       threadId.String(),
		ThreadId: threadId.String(),
		Key:      dbInfo.Key.String(),
		Addr:     dbInfo.Addrs[0].String(),
		Name:     dbInfo.Name,
	}
	_, err = client.Db.Create(context.Background(), a.networkMetadata, common.ThreadsInNetworkSchemaName, threadDB.Instances{threadInNetwork})
	if err != nil {
		log.Printf("Error: %s\n", err.Error())
		return "", err
	}
	if params.ForSale == "true" {
		price, _ := strconv.ParseInt(params.PriceUSD_Cents, 10, 64)
		threadForSale := common.ThreadsForSaleSchema{
			Id:                    threadId.String(),
			ThreadId:              threadId.String(),
			ThreadPrice_USD_Cents: int64(price),
			Owner:                 a.identity,
			OwnerEthAddr:          params.OwnerEthAddr,
			Name:                  dbInfo.Name,
		}
		_, err = client.Db.Create(context.Background(), a.networkMetadata, common.ThreadsForSaleSchemaName, threadDB.Instances{threadForSale})
		if err != nil {
			log.Printf("Error: %s\n", err.Error())
			return "", err
		}
		token := make([]byte, 128)
		rand.Read(token)
		threadClaimToken := base64.StdEncoding.EncodeToString(token)
		threadSaleInfo := common.ThreadPurchasesSchema{
			Id:               threadId.String(),
			ThreadId:         threadId.String(),
			ThreadClaimToken: threadClaimToken,
		}
		_, err = client.Db.Create(context.Background(), a.networkMetadata, common.ThreadPurchaseInfoSchemaName, threadDB.Instances{threadSaleInfo})
		if err != nil {
			log.Printf("Error: %s\n", err.Error())
			return "", err
		}
	}
	client.Db.Close()
	return threadId, nil
}

func (a *Web3DBClient) DeleteDB(params common.DeleteDBParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	// check client a.identity against thread Acl.
	permission := GetThreadPermissions(client, params.ThreadID, a.identity)
	if permission < common.Admin {
		client.Db.Close()
		log.Printf("Thread Permissions: %d", permission)
		return errors.New("permission denied")
	}
	dbInfo, err := client.Db.GetDBInfo(context.Background(), params.ThreadID)
	if err != nil {
		log.Printf("Error retrieving dbInfo.")
		return err
	}
	err = client.Db.DeleteDB(context.Background(), params.ThreadID)
	if err != nil {
		log.Printf("Invalid threadID. Terminating request...")
		return err
	}
	// remove DB from ThreadInNetwork
	query := db.Where("key").Eq(dbInfo.Key.String())
	res, err := client.Db.Find(context.Background(), a.networkMetadata, common.ThreadsInNetworkSchemaName, query, &common.ThreadsInNetworkSchema{})
	if err != nil {
		log.Printf("Error Querying NetworkMetadataThread %s", err.Error())
	}
	threads := res.([]*common.ThreadsInNetworkSchema)
	var deleteMe *common.ThreadsInNetworkSchema
	if len(threads) != 1 {
		log.Printf("More than one thread with key %s", params.ThreadID)
	}
	deleteMe = threads[0]
	err = client.Db.Delete(context.Background(), a.networkMetadata, common.ThreadsInNetworkSchemaName, []string{deleteMe.Id})
	if err != nil {
		log.Printf("Error deleting %s from ThreadInNetworkInfo", deleteMe.Key)
	}
	err = client.Db.Delete(context.Background(), a.networkMetadata, common.ThreadsForSaleSchemaName, []string{deleteMe.Id})
	if err != nil {
		log.Printf("Error deleting %s from ThreadsForSale", deleteMe.Id)
	}
	client.Db.Close()
	return nil
}

func (a *Web3DBClient) ListDBsForSale() ([]*common.ThreadsForSaleSchema, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return make([]*common.ThreadsForSaleSchema, 0), err
	}

	res, err := client.Db.Find(context.Background(), a.networkMetadata, common.ThreadsForSaleSchemaName, &db.Query{}, &common.ThreadsForSaleSchema{})
	if err != nil {
		client.Db.Close()
		return make([]*common.ThreadsForSaleSchema, 0), err
	}

	client.Db.Close()
	return res.([]*common.ThreadsForSaleSchema), err
}

func (a *Web3DBClient) ListDBs() ([]byte, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return []byte(""), err
	}

	dbs, err := client.Db.ListDBs(context.Background())
	if err != nil {
		client.Db.Close()
		return []byte(""), err
	}
	res := make(common.ListDBsResponse, 0, len(dbs))
	for threadId, db := range dbs {
		if threadId.Equals(a.networkMetadata) {
			res = append(res, common.Thread{
				Name: db.Name,
				Id:   threadId,
			})
			continue
		}
		if GetThreadPermissions(client, threadId, a.identity) < common.Reader {
			continue
		}
		res = append(res, common.Thread{
			Name: db.Name,
			Id:   threadId,
		})
	}
	client.Db.Close()
	jsonResponse, err := json.Marshal(res)
	return jsonResponse, err
}

func (a *Web3DBClient) ListCollections(threadId thread.ID) ([]byte, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return []byte(""), err
	}
	collections, err := client.Db.ListCollections(context.Background(), threadId)
	if err != nil {
		client.Db.Close()
		log.Printf("Error with listCollections: %s\n", err.Error())
		return []byte(""), err
	}
	if !thread.ID(threadId).Equals(a.networkMetadata) {
		log.Printf("Thread ID: %s, NetworkMDtId: %s", threadId, a.networkMetadata)
		threadPermission := GetThreadPermissions(client, thread.ID(threadId), a.identity)
		if threadPermission < common.Reader {
			log.Printf("Permission Denied, %s has no read access for thread %s\n", a.identity, threadId)
			return []byte(""), errors.New("permission denied")
		}
	}
	i := 0
	for _, collection := range collections {
		if thread.ID(threadId).Equals(a.networkMetadata) {
			collections[i] = collection
			i++
			continue
		}
		collectionPermission := GetCollectionPermissions(client, thread.ID(threadId), collection.Name, a.identity)
		if collectionPermission >= common.Reader {
			collections[i] = collection
			i++
		}
	}
	collections = collections[:i]
	jsonResponse, err := json.Marshal(collections)
	client.Db.Close()
	return jsonResponse, err
}

func (a *Web3DBClient) CreateCollection(params common.CreateCollectionParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	threadPermissions := GetThreadPermissions(client, params.ThreadID, a.identity)
	if threadPermissions < common.Writer {
		log.Printf("%s does not have write permission for thread %s\n", a.identity, params.ThreadID)
		client.Db.Close()
		return errors.New("permission denied")
	}
	client.Db.NewCollection(context.Background(), params.ThreadID, params.Config)
	collectionName := fmt.Sprintf("CollectionsAcl-%s", params.ThreadID.String())
	// TODO ensure that "acl" is a property
	var instances threadDB.Instances
	for _, entry := range params.Acl {
		aclEntry := common.CollectionAclSchema{
			ID:             "",
			CollectionName: params.Config.Name,
			PubKey:         entry.PubKey,
			Permission:     entry.Permission,
		}
		instances = append(instances, aclEntry)
	}
	ownerAclEntry := common.CollectionAclSchema{
		ID:             "",
		CollectionName: params.Config.Name,
		PubKey:         a.identity,
		Permission:     common.Admin,
	}
	instances = append(instances, ownerAclEntry)
	_, err = client.Db.Create(context.Background(), params.ThreadID, collectionName, instances)
	client.Db.Close()
	if err != nil {
		log.Printf("Error inserting ACL instances in %s: %s\n", collectionName, err.Error())
		return err
	}
	return nil
}

func (a *Web3DBClient) DeleteCollection(params common.DeleteCollectionParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	collectionPermission := GetCollectionPermissions(client, params.ThreadID, params.CollectionName, a.identity)
	if collectionPermission < common.Admin {
		log.Printf("Delete operation prohibited for %s for collection: %s", a.identity, params.CollectionName)
		client.Db.Close()
		return errors.New("permission denied")
	}
	err = client.Db.DeleteCollection(context.Background(), params.ThreadID, params.CollectionName)
	client.Db.Close()
	if err != nil {
		log.Printf("Error deleting collection %s: %s\n", params.CollectionName, err.Error())
		return err
	}
	return nil
}

func (a *Web3DBClient) GetCollectionInfo(collectionName string, threadId thread.ID) (db.CollectionConfig, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return db.CollectionConfig{}, err
	}
	if !a.networkMetadata.Equals(threadId) {
		threadPermissionInfo := GetThreadPermissions(client, threadId, a.identity)
		if threadPermissionInfo < common.Reader {
			client.Db.Close()
			return db.CollectionConfig{}, errors.New("permission denied")
		}
		collectionPermissionInfo := GetCollectionPermissions(client, threadId, collectionName, a.identity)
		if collectionPermissionInfo < common.Reader {
			log.Println("permission denied")
			client.Db.Close()
			return db.CollectionConfig{}, errors.New("permission denied")
		}
	}

	info, err := client.Db.GetCollectionInfo(context.Background(), threadId, collectionName)
	client.Db.Close()
	if err != nil {
		log.Printf("Error getting collection info for %s\n Error: %s\n", collectionName, err.Error())
		return db.CollectionConfig{}, err
	}
	return info, nil
}

func (a *Web3DBClient) CreateInstance(params common.CreateInstanceParams) ([]string, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return nil, err
	}
	collectionPermissions := GetCollectionPermissions(client, params.ThreadID, params.CollectionName, a.identity)
	if collectionPermissions < common.Writer {
		log.Printf("Write operation prohibited for %s", params.CollectionName)
		client.Db.Close()
		return nil, errors.New("permission denied: insufficient collection permissions")
	}
	// this is the actual client data
	var instance map[string]interface{}
	var acl map[string]interface{}
	json.Unmarshal([]byte(params.Instance), &instance)
	json.Unmarshal([]byte(params.Acl), &acl)
	pubKeyStr := a.PublicKey()
	if _, ok := acl[pubKeyStr]; !ok {
		log.Println("no ACL entry for Web3DB node. Please include Web3DB with read permissions in the ACL")
		client.Db.Close()
		return nil, errors.New("no ACL entry for Web3DB node. Please include Web3DB with read permissions in the ACL")
	}
	if _, ok := acl[a.identity]; !ok {
		msg := fmt.Sprintf("no ACL entry for self. Please include %s with admin permissions in the ACL", a.identity)
		client.Db.Close()
		log.Println(msg)
		return nil, errors.New(msg)
	}
	err = validateAcl(acl, a.identity, pubKeyStr)
	if err != nil {
		client.Db.Close()
		return nil, err
	}
	adminAclEntry := acl[pubKeyStr].(map[string]interface{})
	k1Encrypted := adminAclEntry["seed"].(string)
	k1, err := common.ECCDecrypt(a.selfId, k1Encrypted)
	if err != nil {
		client.Db.Close()
		log.Printf("Error decrypting k1: %s\n", err.Error())
		return nil, err
	}
	for attribute, value := range instance {
		metaData := attribute == "_id" || attribute == "acl" || attribute == "_mod"
		public := strings.HasPrefix(attribute, "_")
		private := !(metaData || public)
		if private {
			// only decrypt private attribtues
			decryptedAttr := common.AesGcmDecrypt(k1, value.(string))
			instance[attribute] = decryptedAttr
		}
	}
	// access like json
	instance["acl"] = acl

	ids, err := client.Db.Create(context.Background(), params.ThreadID, params.CollectionName, threadDB.Instances{instance})
	client.Db.Close()
	if err != nil {
		log.Printf("Error: %s\n", err.Error())
		return nil, err
	}

	return ids, nil
}

func (a *Web3DBClient) Find(threadId thread.ID, collectionName string, query db.Query) ([]map[string]interface{}, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return nil, err
	}
	if !threadId.Equals(a.networkMetadata) {
		collectionPermissions := GetCollectionPermissions(client, threadId, collectionName, a.identity)
		if collectionPermissions < common.Reader {
			client.Db.Close()
			log.Printf("Read operation prohibited for %s", collectionName)
			return nil, errors.New(" permission denied")
		}
	}
	var dummy interface{} // used to extrapolate structure for results
	results, err := client.Db.Find(context.Background(), threadId, collectionName, &query, &dummy)
	if err != nil {
		client.Db.Close()
		log.Printf(" Error: %s\n", err.Error())
		return nil, err
	}
	adminPubKey := a.PublicKey()
	clientPubKey := a.identity
	instances := results.([]*interface{})
	var res []map[string]interface{}
	for _, item := range instances {
		instance := (*item).(map[string]interface{})
		if threadId.Equals(a.networkMetadata) {
			acl := make(map[string]interface{})
			instance["acl"] = acl
			res = append(res, instance)
			continue
		}
		if _, exists := instance["acl"]; !exists {
			client.Db.Close()
			log.Printf("no acl data... instance %s is now unattainable. consider deleting.", instance["_id"].(string))
			return nil, fmt.Errorf("no acl data... instance %s is now unattainable, consider deleting", instance["_id"].(string))
		}
		acl := instance["acl"].(map[string]interface{})
		if _, exists := acl[adminPubKey]; !exists {
			client.Db.Close()
			log.Printf("no admin acl data... instance %s is now unattainable. consider deleting.", instance["_id"].(string))
			return nil, fmt.Errorf("no admin acl data... instance %s is now unattainable, consider deleting", instance["_id"].(string))
		}
		adminAclEntry := acl[adminPubKey].(map[string]interface{})
		if _, exists := adminAclEntry["seed"]; !exists {
			client.Db.Close()
			log.Printf("no admin acl decryption seed... instance %s is now unattainable. consider deleting.", instance["_id"].(string))
			return nil, fmt.Errorf("no admin decryption seed... instance %s is now unattainable, consider deleting", instance["_id"].(string))
		}
		if _, exists := acl[clientPubKey]; !exists {
			client.Db.Close()
			log.Printf("No permissions for %s in instance: %s", clientPubKey, instance["_id"].(string))
			continue
		}
		clientAclEntry := acl[clientPubKey].(map[string]interface{})
		if _, exists := clientAclEntry["permissions"]; !exists {
			client.Db.Close()
			log.Printf("No permissions for %s in instance: %s", clientPubKey, instance["_id"].(string))
			continue
		}
		permissions := common.Permissions(clientAclEntry["permissions"].(float64))
		if permissions < common.Reader {
			client.Db.Close()
			log.Printf("Read permission denied for %s in instance: %s", clientPubKey, instance["_id"].(string))
			continue
		}
		if _, exists := clientAclEntry["seed"]; !exists {
			client.Db.Close()
			log.Printf("No decryption seed for %s in instance: %s", clientPubKey, instance["_id"].(string))
			continue
		}
		for pubKey := range acl {
			if pubKey != clientPubKey && permissions < common.Writer {
				delete(acl, pubKey)
			}
		}
		instance["acl"] = acl
		res = append(res, instance)
	}
	client.Db.Close()
	return res, nil
}

func (a *Web3DBClient) GetThreadAcl(threadId thread.ID) (interface{}, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return nil, err
	}
	if !threadId.Equals(a.networkMetadata) {
		threadPermissions := GetThreadPermissions(client, threadId, a.identity)
		if threadPermissions < common.Admin {
			client.Db.Close()
			err := fmt.Sprintf("admin operations prohibited for %s for thread: %s\n", a.identity, threadId)
			log.Println(err)
			return nil, errors.New(err)
		}
	}
	var dummy common.ThreadAclSchema
	results, err := client.Db.Find(context.Background(), threadId, fmt.Sprintf("ThreadAcl-%s", threadId.String()), &db.Query{}, &dummy)
	client.Db.Close()
	if err != nil {
		errMsg := fmt.Sprintf("error querying for thread acl: %s\n", err.Error())
		log.Println(errMsg)
		return nil, errors.New(errMsg)
	}
	return results, nil
}

func (a *Web3DBClient) GetCollectionAcl(collectionName string, threadId thread.ID) (interface{}, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return nil, err
	}
	collectionPermissions := GetCollectionPermissions(client, threadId, collectionName, a.identity)
	if collectionPermissions < common.Admin {
		client.Db.Close()
		err := fmt.Sprintf("admin operations prohibited for %s for collection: %s\n", a.identity, collectionName)
		log.Println(err)
		return nil, errors.New(err)
	}
	var dummy common.ThreadAclSchema
	query := db.Where("collectionName").Eq(collectionName)
	results, err := client.Db.Find(context.Background(), threadId, fmt.Sprintf("CollectionsAcl-%s", threadId.String()), query, &dummy)
	client.Db.Close()
	if err != nil {
		errMsg := fmt.Sprintf("error querying for thread acl: %s\n", err.Error())
		log.Println(errMsg)
		return nil, errors.New(errMsg)
	}
	return results, nil
}

func (a *Web3DBClient) GetInstanceAcl(collectionName string, threadId thread.ID, instanceId string) (interface{}, error) {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return nil, err
	}
	var dummy interface{} // used to extrapolate structure for results
	query := db.Where("_id").Eq(instanceId)
	results, err := client.Db.Find(context.Background(), threadId, collectionName, query, &dummy)
	instances := results.([]*interface{})
	if err != nil {
		client.Db.Close()
		log.Printf("Error: %s\n", err.Error())
		return nil, err
	}
	if len(instances) == 0 {
		client.Db.Close()
		log.Printf("instance not found")
		return nil, nil
	}
	instance := (*instances[0]).(map[string]interface{})
	if _, exists := instance["acl"]; !exists {
		client.Db.Close()
		log.Printf("no acl data... instance %s is now unattainable. consider deleting.", instance["_id"].(string))
		return nil, fmt.Errorf("no acl data... instance %s is now unattainable, consider deleting", instance["_id"].(string))
	}
	acl := instance["acl"].(map[string]interface{})
	permission, _, _, err := a.GetInstanceData(client, threadId, collectionName, instanceId, a.identity)
	if err != nil {
		client.Db.Close()
		log.Printf("An error occured retireving instance data for %s in collection %s in thread %s\n", instanceId, collectionName, threadId)
		return nil, err
	}
	client.Db.Close()
	if permission < common.Admin {
		log.Printf("insufficient permissions for %s for instance %s\n", a.identity, instanceId)
		return nil, errors.New("permission denied")
	}
	return acl, nil
}

func (a *Web3DBClient) UpdateThreadAclEntry(params common.UpdateThreadAclEntryParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	log.Printf("\n %s %s %d\n", params.PubKey, params.ThreadID, params.Permissions)
	threadPermissions := GetThreadPermissions(client, params.ThreadID, a.identity)
	if threadPermissions < common.Admin {
		client.Db.Close()
		err := fmt.Sprintf("admin operations prohibited for %s for thread: %s\n", a.identity, params.ThreadID)
		log.Println(err)
		return errors.New(err)
	}
	collectionName := fmt.Sprintf("ThreadAcl-%s", params.ThreadID)
	query := db.Where("pubKey").Eq(string(params.PubKey))
	results, err := client.Db.Find(context.Background(), params.ThreadID, collectionName, query, &common.ThreadAclSchema{})
	if err != nil {
		client.Db.Close()
		log.Printf("An error occured querying %s in thread %s \n", collectionName, params.ThreadID)
		return err
	}
	entries := results.([]*common.ThreadAclSchema)
	if len(entries) > 0 {
		// update operation
		entry := entries[0]
		if params.Permissions != entry.Permission {
			entry.Permission = params.Permissions
			client.Db.Save(context.Background(), params.ThreadID, collectionName, threadDB.Instances{entry})
		}
	} else {
		// insert operation
		instance := common.ThreadAclSchema{
			ID:         "",
			Permission: params.Permissions,
			PubKey:     common.PubKey(params.PubKey),
		}
		_, err = client.Db.Create(context.Background(), params.ThreadID, collectionName, threadDB.Instances{instance})
		if err != nil {
			client.Db.Close()
			log.Printf("Error: %s\n", err.Error())
			return err
		}
	}
	client.Db.Close()
	return nil
}

func (a *Web3DBClient) UpdateCollectionAclEntry(params common.UpdateCollectionAclEntryParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	if params.PubKey == a.identity {
		return errors.New("attempts to modify self permissions are forbidden")
	}
	permissions := GetCollectionPermissions(client, params.ThreadID, params.CollectionName, a.identity)
	if permissions < common.Admin {
		client.Db.Close()
		err := fmt.Sprintf("admin operations prohibited for %s for collection: %s\n", a.identity, params.CollectionName)
		log.Println(err)
		return errors.New(err)
	}
	collectionName := fmt.Sprintf("CollectionsAcl-%s", params.ThreadID)
	query := db.Where("pubKey").Eq(string(params.PubKey)).And("collectionName").Eq(params.CollectionName)
	results, err := client.Db.Find(context.Background(), params.ThreadID, collectionName, query, &common.CollectionAclSchema{})
	if err != nil {
		client.Db.Close()
		log.Printf("An error occured querying %s in thread %s  ERR: %s\n", collectionName, params.ThreadID, err.Error())
		return err
	}
	entries := results.([]*common.CollectionAclSchema)
	if len(entries) > 0 {
		// update operation
		pubKey := entries[0]
		if params.Permissions != pubKey.Permission {
			pubKey.Permission = params.Permissions
			client.Db.Save(context.Background(), params.ThreadID, collectionName, threadDB.Instances{pubKey})
		}
	} else {
		// insert operation
		instance := common.CollectionAclSchema{
			ID:             "",
			Permission:     params.Permissions,
			PubKey:         params.PubKey,
			CollectionName: params.CollectionName,
		}
		_, err = client.Db.Create(context.Background(), params.ThreadID, collectionName, threadDB.Instances{instance})
		if err != nil {
			client.Db.Close()
			log.Printf("Error: %s\n", err.Error())
			return err
		}
	}
	client.Db.Close()
	return nil
}

func (a *Web3DBClient) UpdateInstanceAclEntry(params common.UpdateInstanceAclEntryParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}

	permissions, _, _, err := a.GetInstanceData(client, params.ThreadID, params.CollectionName, params.InstanceID, a.identity)
	if err != nil {
		client.Db.Close()
		log.Printf("An error occured retireving instance data for %s in collection %s in thread %s\n", params.InstanceID, params.CollectionName, params.ThreadID)
		return err
	}
	if permissions < common.Admin {
		client.Db.Close()
		err := fmt.Sprintf("admin operations prohibited for %s for instance: %s\n", a.identity, params.InstanceID)
		log.Println(err)
		return errors.New(err)
	}
	pk := string(params.PubKey)
	if pk == a.identity {
		return errors.New("attempts to modify self permissions are forbidden")
	}
	var dummy interface{} // used to extrapolate structure for results
	query := db.Where("_id").Eq(params.InstanceID)
	results, err := client.Db.Find(context.Background(), params.ThreadID, params.CollectionName, query, &dummy)
	instances := results.([]*interface{})
	if err != nil {
		client.Db.Close()
		log.Printf("Error: %s\n", err.Error())
		return err
	}
	if len(instances) == 0 {
		client.Db.Close()
		log.Printf("instance not found")
		return errors.New("instance not found")
	}
	instance := (*instances[0]).(map[string]interface{})
	if _, exists := instance["acl"]; !exists {
		client.Db.Close()
		log.Printf("no acl data... instance %s is now unattainable. consider deleting.", instance["_id"].(string))
		return fmt.Errorf("no acl data... instance %s is now unattainable, consider deleting", instance["_id"].(string))
	}
	acl := instance["acl"].(map[string]interface{})
	var entry map[string]interface{}
	if _, exists := acl[pk]; !exists {
		log.Printf("no acl entry for %s... creating a new one\n", pk)
		if params.Seed == "" && params.Permissions >= common.Reader {
			client.Db.Close()
			log.Println("attempted to add new acl entry without providing decryption seed")
			return errors.New("attempted to add new acl entry without providing decryption seed")
		}
		entry = make(map[string]interface{})
	} else {
		entry = acl[pk].(map[string]interface{})
	}
	entry["permissions"] = params.Permissions
	entry["seed"] = params.Seed
	acl[pk] = entry
	instance["acl"] = acl
	err = client.Db.Save(context.Background(), params.ThreadID, params.CollectionName, threadDB.Instances{instance})
	client.Db.Close()
	return err
}

func (a *Web3DBClient) DeleteInstance(params common.DeleteInstanceParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	permissions, _, _, err := a.GetInstanceData(client, params.ThreadID, params.CollectionName, params.InstanceID, a.identity)
	if err != nil {
		client.Db.Close()
		log.Printf("An error occured retireving instance data for %s in collection %s in thread %s\n", params.InstanceID, params.CollectionName, params.ThreadID)
		return err
	}
	if permissions < common.Admin {
		client.Db.Close()
		err := fmt.Sprintf("admin operations prohibited for %s for instance: %s\n", a.identity, params.InstanceID)
		log.Println(err)
		return errors.New(err)
	}
	err = client.Db.Delete(context.Background(), params.ThreadID, params.CollectionName, []string{params.InstanceID})
	client.Db.Close()
	return err
}

func (a *Web3DBClient) UpdateInstance(params common.UpdateInstanceParams) error {
	client, err := client.New(a.ThreadDBAddr, a.selfId)
	if err != nil {
		return err
	}
	var instance map[string]interface{}
	json.Unmarshal([]byte(params.Instance), &instance)
	if _, ok := instance["_id"]; !ok {
		log.Println("missing field: _id")
		client.Db.Close()
		return errors.New("missing field: _id")
	}
	instanceId := instance["_id"].(string)
	permissions, _, _, err := a.GetInstanceData(client, params.ThreadID, params.CollectionName, instanceId, a.identity)
	if err != nil {
		log.Printf("An error occured retireving instance data for %s in collection %s in thread %s\n", instanceId, params.CollectionName, params.ThreadID)
		client.Db.Close()
		return err
	}
	if permissions < common.Writer {
		err := fmt.Sprintf("admin operations prohibited for %s for instance: %s\n", a.identity, instanceId)
		log.Println(err)
		client.Db.Close()
		return errors.New(err)
	}
	var acl map[string]interface{}
	pubKeyStr := a.PublicKey()
	if _, ok := instance["acl"]; !ok {
		log.Println("no ACL entry. Please include the ACL")
		client.Db.Close()
		return errors.New("no ACL entry. Please include the ACL")
	}
	acl = instance["acl"].(map[string]interface{})
	if _, ok := acl[pubKeyStr]; !ok {
		log.Println("no ACL entry for Web3DB. Please include Web3DB with read permissions in the ACL")
		client.Db.Close()
		return errors.New("no ACL entry for Web3DB. Please include Web3DB with read permissions in the ACL")
	}
	if _, ok := acl[a.identity]; !ok {
		msg := fmt.Sprintf("no ACL entry for self. Please include %s with admin permissions in the ACL", a.identity)
		client.Db.Close()
		log.Println(msg)
		return errors.New(msg)
	}
	err = validateAcl(acl, a.identity, pubKeyStr)
	if err != nil {
		client.Db.Close()
		return err
	}

	adminAclEntry := acl[pubKeyStr].(map[string]interface{})
	k1Encrypted := adminAclEntry["seed"].(string)
	k1, err := common.ECCDecrypt(a.selfId, k1Encrypted)
	if err != nil {
		client.Db.Close()
		log.Printf("Error decrypting k1: %s\n", err.Error())
		return err
	}
	for attribute, value := range instance {
		metaData := attribute == "_id" || attribute == "acl" || attribute == "_mod"
		public := strings.HasPrefix(attribute, "_")
		private := !(metaData || public)
		if private {
			// only decrypt private attribtues
			decryptedAttr := common.AesGcmDecrypt(k1, value.(string))
			instance[attribute] = decryptedAttr
		}
	}
	// access like json
	instance["acl"] = acl
	err = client.Db.Save(context.Background(), params.ThreadID, params.CollectionName, threadDB.Instances{instance})
	client.Db.Close()
	return err
}

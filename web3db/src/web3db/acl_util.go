package web3db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"web3db/src/common"
	client "web3db/src/threaddb"

	"github.com/textileio/go-threads/core/thread"
	db "github.com/textileio/go-threads/db"
)

func GetThreadPermissions(c client.ThreadDBClient, tId thread.ID, identity string) common.Permissions {
	clientPubKey := identity
	query := db.Where("pubKey").Eq(string(clientPubKey))
	entries, err := c.Db.Find(context.Background(), tId, fmt.Sprintf("ThreadAcl-%s", tId.String()), query, &common.ThreadAclSchema{})
	if err != nil {
		log.Printf("An error occured querying %s for Thread ACL permissions for %s\n: %s", fmt.Sprintf("ThreadAcl-%s", tId.String()), identity, err.Error())
		return common.None
	}
	if len(entries.([]*common.ThreadAclSchema)) < 1 {
		// no acl entry. choose default.
		query := db.Where("pubKey").Eq("*")
		log.Printf("No ACL Entry for %s\n", clientPubKey)
		defaultEntries, err := c.Db.Find(context.Background(), tId, fmt.Sprintf("ThreadAcl-%s", tId), query, &common.ThreadAclSchema{})
		if err != nil {
			log.Printf("An error occured querying %s for Thread ACL permissions for %s\n: %s", fmt.Sprintf("ThreadAcl-%s", tId.String()), "*", err.Error())
			return common.None
		}
		if len(defaultEntries.([]*common.ThreadAclSchema)) < 1 {
			log.Printf("No default Thread ACL entry.")
			return common.None
		} else {
			entry := defaultEntries.([]*common.ThreadAclSchema)[0]
			return entry.Permission
		}
	} else {
		entry := entries.([]*common.ThreadAclSchema)[0]
		return entry.Permission
	}
}

func GetCollectionPermissions(c client.ThreadDBClient, tId thread.ID, collectionName string, identity string) common.Permissions {
	aclCollectionName := fmt.Sprintf("CollectionsAcl-%s", tId.String())
	query := db.Where("pubKey").Eq(identity).And("collectionName").Eq(collectionName)
	entries, err := c.Db.Find(context.Background(), tId, aclCollectionName, query, &common.CollectionAclSchema{})
	if err != nil {
		log.Printf("An error occured querying %s for Collection ACL permissions for %s, Err: %s\n", fmt.Sprintf("CollectionsAcl-%s", tId.String()), identity, err.Error())
		return common.None
	}
	if len(entries.([]*common.CollectionAclSchema)) < 1 {
		// no acl entry. choose default.
		query := db.Where("pubKey").Eq("*").And("collectionName").Eq(collectionName)
		defaultEntries, err := c.Db.Find(context.Background(), tId, aclCollectionName, query, &common.CollectionAclSchema{})
		if err != nil {
			log.Printf("An error occured querying %s for Collection permissions for %s\n: %s", aclCollectionName, "*", err.Error())
			return common.None
		}
		if len(defaultEntries.([]*common.CollectionAclSchema)) < 1 {
			return common.None
		} else {
			entry := defaultEntries.([]*common.CollectionAclSchema)[0]
			return entry.Permission
		}
	} else {
		entry := entries.([]*common.CollectionAclSchema)[0]
		return entry.Permission
	}
}

func (a *Web3DBClient) GetInstanceData(c client.ThreadDBClient, tId thread.ID, collectionName string, instanceId string, identity string) (common.Permissions, map[string]interface{}, map[string]interface{}, error) {
	var result interface{}
	pk := identity
	err := c.Db.FindByID(context.Background(), tId, collectionName, instanceId, &result)
	if err != nil {
		log.Printf("An error occured querying %s for Collection ACL permissions for %s, Err: %s\n", fmt.Sprintf("CollectionsAcl-%s", tId.String()), identity, err.Error())
		return common.None, nil, nil, errors.New("instance does not exist")
	}
	instance := result.(map[string]interface{})
	if _, exists := instance["acl"]; !exists {
		log.Printf("no acl data... instance %s is now unattainable. consider deleting.", instance["_id"].(string))
		return common.None, nil, nil, fmt.Errorf("no acl data... instance %s is now unattainable, consider deleting", instance["_id"].(string))
	}
	acl := instance["acl"].(map[string]interface{})
	if _, exists := acl[pk]; !exists {
		// no acl data for this client. no permissions
		return common.None, nil, nil, nil
	}
	entry := acl[pk].(map[string]interface{})
	if _, exists := entry["permissions"]; !exists {
		// no permission data for this client. no permissions.
		return common.None, nil, nil, nil
	}
	permissions := entry["permissions"].(float64)
	return common.Permissions(permissions), instance, acl, nil
}

func validateAcl(acl map[string]interface{}, clientPubKey string, adminPubKey string) error {
	for pubKey, entry := range acl {
		if _, exists := entry.(map[string]interface{})["seed"]; !exists {
			log.Println("Instance ACL: required field missing: seed")
			return errors.New("instance ACL: required field missing: seed")
		}
		if _, exists := entry.(map[string]interface{})["permissions"]; !exists {
			log.Println("Instance ACL: required field missing: permissions")
			return errors.New("instance ACL: required field missing: permissions")
		}
		seed := entry.(map[string]interface{})["seed"]
		permissions := common.Permissions(entry.(map[string]interface{})["permissions"].(float64))
		if seed == "" && permissions >= common.Reader {
			log.Println("Instance ACL: invalid field: seed")
			return errors.New("instance ACL: required field missing: seed")
		}
		// if pubKey == clientPubKey && permissions != common.Admin {
		// 	log.Println("Instance ACL: attempted to remove self admin permissions")
		// 	return errors.New("admin permissions required for self acl entry")
		// }
		if pubKey == adminPubKey && permissions != common.Reader {
			log.Println("Instance ACL: insufficient permissions for self")
			return errors.New("reader permissions required for web3db node acl entry")
		}
	}
	return nil
}

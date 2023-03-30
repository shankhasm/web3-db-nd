package common

import (
	"github.com/textileio/go-threads/core/thread"
	"github.com/textileio/go-threads/db"
)

type PubKey string
type Identity []byte

type Permissions int

const (
	None   Permissions = 0
	Reader Permissions = 1
	Writer Permissions = 2
	Admin  Permissions = 4
)

// api key storage
type APIKeysSchema struct {
	ID      string `json:"_id"`
	Creator string `json:"creator"` // Client identity of the creator of this key
	Key     string `json:"key"`     // API Key string
}

type Thread struct {
	Name string    `json:"name"`
	Id   thread.ID `json:"id"`
}

// permission info for threads
type ThreadPermissionInfo struct {
	Permission int    `json:"permission"` // clients permission level for the schema
	PubKey     string `json:"pubKey"`     // thread db pub key of the client
}

// Created by default when a new Thread is created.
type ThreadAclSchema struct {
	ID         string      `json:"_id"`        // ID of th instance, required field
	PubKey     PubKey      `json:"pubKey"`     // Public Key of the client with granted permissions
	Permission Permissions `json:"permission"` // permission level the Public Key has with this thread
}

type CollectionAclSchema struct {
	ID             string      `json:"_id"`            // ID of the instance, required field
	CollectionName string      `json:"collectionName"` // the collection name
	PubKey         string      `json:"pubKey"`         // Public Key of the client with granted permissions
	Permission     Permissions `json:"permission"`     // permission level the Public Key has with the collection name
}

// permission info for collections
type CollectionPermissionInfo struct {
	Permission Permissions `json:"permission"` // clients permission level for the schema
	PubKey     string      `json:"pubKey"`     // thread db pub key of the client
}

// expected json for CreateCollection endpoint.
type CreateCollectionParams struct {
	ThreadID thread.ID                  `json:"threadId"` // thread the collection will live in
	Config   db.CollectionConfig        `json:"config"`
	Acl      []CollectionPermissionInfo `json:"acl"` // access control list
}

type DeleteCollectionParams struct {
	ThreadID       thread.ID `json:"threadId"`
	CollectionName string    `json:"collectionName"`
}

// expected json for NewDB endpoint.
type NewDBParams struct {
	Name           string                 `json:"name"`
	Acl            []ThreadPermissionInfo `json:"acl"`
	ForSale        string                 `json:"forSale"`
	OwnerEthAddr   string                 `json:"ownerEthAddr"`
	PriceUSD_Cents string                 `json:"priceUsdCents"`
}

// expected json for DeleteDB endpoint.
type DeleteDBParams struct {
	ThreadID thread.ID `json:"threadId"`
}

// expected json for CreateInstance endpoint.
type CreateInstanceParams struct {
	ThreadID       thread.ID `json:"threadID"`
	CollectionName string    `json:"collectionName"`
	Instance       string    `json:"instance"` // instance json object string
	Acl            string    `json:"acl"`      // acl json object string
}

type UpdateThreadAclEntryParams struct {
	ThreadID    thread.ID   `json:"threadId"`
	PubKey      string      `json:"pubKey"`
	Permissions Permissions `json:"permissions"`
}

type UpdateCollectionAclEntryParams struct {
	ThreadID       thread.ID   `json:"threadId"`
	CollectionName string      `json:"collectionName"`
	PubKey         string      `json:"pubKey"`
	Permissions    Permissions `json:"permissions"`
}

type UpdateInstanceAclEntryParams struct {
	ThreadID       thread.ID   `json:"threadId"`
	CollectionName string      `json:"collectionName"`
	InstanceID     string      `json:"instanceId"`
	PubKey         string      `json:"pubKey"`
	Permissions    Permissions `json:"permissions"`
	Seed           string      `json:"seed"`
}

type DeleteInstanceParams struct {
	ThreadID       thread.ID `json:"threadId"`
	CollectionName string    `json:"collectionName"`
	InstanceID     string    `json:"instanceId"`
}

type UpdateInstanceParams struct {
	ThreadID       thread.ID `json:"threadId"`
	CollectionName string    `json:"collectionName"`
	Instance       string    `json:"instance"`
}

const NetworkMetadataThreadName = "networkMetadata"
const NodeRecordsSchemaName string = "nodeRecords"
const NodeQueueSchemaName string = "nodeQueue"
const NodeRecordsMetadataSchemaName string = "nodeRecordsMetadata"
const MasterNodeQueueName string = "masterNodeQueue"
const ThreadsInNetworkSchemaName string = "threadsInNetwork"
const ThreadsForSaleSchemaName string = "threadsForSale"
const ThreadPurchaseInfoSchemaName string = "threadsPurchaseInfo"
const BootStrapperChannel = "BootstrapperChannel"
const MasterNodeChannel = "MasterNodeChannel"

const (
	StartNodeQueueMaintenance = 1
	StopNodeQueueMaintenance  = 0
)

// shared database amongst all peers
// contains info about Web3DB peers on this network
type NodeRecordsSchema struct {
	ThreadDbId             string `json:"_id"`
	Id                     string `json:"peerId"`
	MultiAddr              string `json:"multiAddr"`
	ThreadDbPort           int    `json:"threadDbPort"`
	MasterNodeCommsPort    int    `json:"masterNodeCommsPort"`
	BootstrappingCommsPort int    `json:"bootstrappingCommsPort"`
	IsMasterNode           bool   `json:"isMasterNode"`
	InQueue                bool   `json:"inQueue"`
	RecentlyInQueue        bool   `json:"recentlyInQueue"`
	Ttl                    int    `json:"ttl"`
}

type ThreadsForSaleSchema struct {
	Id                    string `json:"_id"`
	ThreadId              string `json:"threadId"`
	ThreadPrice_USD_Cents int64  `json:"priceUsdCents"`
	Owner                 string `json:"owner"`
	OwnerEthAddr          string `json:"ownerEthAddr"`
	Name                  string `json:"name"`
}

type ThreadPurchasesSchema struct {
	Id               string `json:"_id"`
	ThreadId         string `json:"threadId"`
	ThreadClaimToken string `json:"threadClaimToken"`
}

type NodeRecordsMetadataSchema struct {
	Id             string `json:"_id"`
	NumRecords     int    `json:"numRecords"`
	NumMasterNodes int    `json:"numMasterNodes"`
	QueueSize      int    `json:"queueSize"`
}

// the queue of peers ready to accept database requests from clients
type NodeQueueSchema struct {
	ThreadDbId   string `json:"_id"`
	ThreadDbPort int    `json:"threadDbPort"`
	Id           string `json:"peerId"`
	MultiAddr    string `json:"multiAddr"`
	AssignMaster bool   `json:"assignMaster"`
	Timestamp    string `json:"timestamp"`
}

// contains thread data for all threads on the network
// used for bootstrapping a new peer into the network
// when a peer joins, it subscribes to each thread on the network
// essentially a wrapper around DBInfo
type ThreadsInNetworkSchema struct {
	Id       string `json:"_id"`
	ThreadId string `json:"threadId"`
	Addr     string `json:"addr"`
	Key      string `json:"key"`
	Name     string `json:"name"`
}

type ListDBsResponse []Thread

package bootstrapper

import (
	"context"
	"log"
	"time"
	"web3db/src/config"
	"web3db/src/pb/peer_comms/bootstrapper_comms"
	client "web3db/src/threaddb"

	common "web3db/src/common"

	"github.com/alecthomas/jsonschema"
	ma "github.com/multiformats/go-multiaddr"
	threadDB "github.com/textileio/go-threads/api/client"

	"github.com/textileio/go-threads/core/thread"
	"github.com/textileio/go-threads/db"
)

/**
*  Bootstrapper is in charge of:
* 	- Creating a new Web3DB network.
*   - Joining an existing Web3DB network (by communicating with other Bootstrap servers).
*   - Listening for requests to Join the network from new peers (by acting as a Bootstrap server).
 */
type Bootstrapper struct {
	client                   *bootstrapper_comms.BootstrappingCommsClient // used to communicate with Bootstrap servers
	BootstrapperMultiAddr    ma.Multiaddr                                 // the address of the external bootstrapper to connect to
	NetworkMetadataThreadId  thread.ID
	threadDbAddr             string
	selfId                   thread.Identity
	BootstrapperCommsChannel chan int
	server                   *bootstrapper_comms.BootstrappingCommsServer
	cfg                      *config.AppConfig
	logger                   *log.Logger
}

// creates a new Bootstrapper struct.
func New(cfg *config.AppConfig) Bootstrapper {
	if cfg.BootstrapperMultiaddr == "" {
		return Bootstrapper{
			selfId:                  cfg.GetThreadIdentity(),
			threadDbAddr:            cfg.ThreadDBAddr,
			NetworkMetadataThreadId: cfg.GetNetworkMetadataThreadId(),
			cfg:                     cfg,
			logger:                  cfg.BootstrapperLogger,
		}
	}
	addr, _ := ma.NewMultiaddr(cfg.BootstrapperMultiaddr)
	return Bootstrapper{
		BootstrapperMultiAddr: addr,
		selfId:                cfg.GetThreadIdentity(),
		threadDbAddr:          cfg.ThreadDBAddr,
		cfg:                   cfg,
		logger:                cfg.BootstrapperLogger,
	}
}

// Joins an existing Web3DB network.
func (bootstrapper *Bootstrapper) JoinNetwork() {
	if bootstrapper.BootstrapperMultiAddr == nil {
		// can't join without the address of a Bootstrap server.
		bootstrapper.logger.Fatal("Cannot Join Peer Network: Empty Bootstrap Multiaddress")
	}
	// initialize gRPC client
	bootstrapper.client, _ = bootstrapper_comms.NewBootstrappingCommsClient(bootstrapper.cfg.BootstrapperMultiaddr)

	// determine if this Peer has joined the network before.
	// i.e., is this peer rejoining the network
	// if the "NetworkMetadataThreadId" exists in the config.yaml file, it is assumed that this peer has already joined.
	if !bootstrapper.cfg.NetworkMetadataThreadIdInitialized() {
		bootstrapper.joinNetwork()
	} else {
		bootstrapper.reJoinNetwork()
	}

}

func (bootstrapper *Bootstrapper) reJoinNetwork() {
	// you already have joined this network
	// this server must have gone offline
	bootstrapper.logger.Print("Attempting to rejoin Web3DB network")
	// ensure you're in the NodeRecords table (sanity check)
	if !bootstrapper.IsInNodeRecords() {
		// add self if not
		bootstrapper.logger.Print("Self entry does not exist in Node Records")
		err := bootstrapper.addSelfToNodeRecords(false, false)
		if err != nil {
			bootstrapper.logger.Printf("Error adding self to NodeRecords")
		}
	}
	// ensure you're subscribed to all threads in the network
	// during downtime, some threads may have been deleted/added

	// listDBs from your local Thread DB instance
	subscribedThreads, err := bootstrapper.findSubscribedThreads()
	if err != nil {
		return
	}
	// query ThreadsInNetworkInfo
	allThreads, err := bootstrapper.findNetworkThreads()
	if err != nil {
		return
	}
	// subscribe to all threads in ThreadsInNetworkInfo results that are not a subset of ListDBs() output
	var threadsToSubscribe []*common.ThreadsInNetworkSchema
	for _, t := range allThreads {
		if _, exists := subscribedThreads[thread.ID(t.ThreadId)]; !exists {
			threadsToSubscribe = append(threadsToSubscribe, t)
		}
	}
	err = bootstrapper.subscribeToThreads(threadsToSubscribe)
	if err != nil {
		bootstrapper.logger.Printf("Error subscribing to missed Network Threads %s", err)
		return
	}
	// // delete all threads no longer in the ThreadsInNetworkInfo table
	// var threadsToDelete []db.Info
	// for subscribedThreadId, subscribedThread := range subscribedThreads {
	// 	containsThread := false
	// 	for _, t := range allThreads {
	// 		containsThread = subscribedThreadId.String() == t.ThreadId
	// 	}
	// 	if containsThread {
	// 		threadsToDelete = append(threadsToDelete, subscribedThread)
	// 	}
	// }
}

func (bootstrapper *Bootstrapper) foo() error {
	client, _ := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)

	opts := make([]threadDB.ListenOption, 0)
	opt := threadDB.ListenOption{
		Type:       threadDB.ListenAll,
		Collection: common.ThreadsInNetworkSchemaName,
	}
	opts = append(opts, opt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := client.Db.Listen(ctx, bootstrapper.NetworkMetadataThreadId, opts)
	if err != nil {
		bootstrapper.logger.Print("Error Listening for Delete events on NodeRecords")
		return err
	}
	for event := range events {
		// Handle event
		if event.Action.Type == threadDB.ActionCreate {
			// subscribe to new thread

		} else if event.Action.Type == threadDB.ActionDelete {
			// YAGNI
		} else if event.Action.Type == threadDB.ActionSave {
			// YAGNI
		}
	}
	return nil
}
func (bootstrapper *Bootstrapper) subscribeToThreads(threads []*common.ThreadsInNetworkSchema) error {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return err
	}
	for _, t := range threads {
		bootstrapper.SubscribeToThread(t, &client)
	}
	return err
}

func (bootstrapper *Bootstrapper) SubscribeToThread(t *common.ThreadsInNetworkSchema, client *client.ThreadDBClient) error {
	key, err := thread.KeyFromString(t.Key)
	if err != nil {
		bootstrapper.logger.Printf("Error Extracting Thread Service Key %s", err)
		return err
	}
	err = client.Db.NewDBFromAddr(context.Background(), ma.StringCast(t.Addr), key, db.WithNewManagedBackfillBlock(true))
	if err != nil {
		bootstrapper.logger.Printf("Error subscribing to Thread %s", err)
		return err
	}
	return nil
}
func (bootstrapper *Bootstrapper) joinNetwork() {
	bootstrapper.logger.Printf("Joining Network via Peer %s", bootstrapper.cfg.BootstrapperMultiaddr)
	// retrieve Network Metadata Thread info from the Bootstrap server
	dbInfo, err := bootstrapper.client.SendJoinRequest(bootstrapper.selfId)
	if err != nil {
		bootstrapper.logger.Printf("Error Sending JoinRequest to Bootstrapper %s", err)
		return
	}
	// subscribe to the Network Metadata Thread
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		bootstrapper.logger.Printf("Error Creating Client in JoinRequest to Bootstrapper %s", err)
		return
	}
	subscribedThreads, err := bootstrapper.findSubscribedThreads()
	if err != nil {
		return
	}
	alreadySubscribed := false
	// check if you're already subscribed to the Network Metadata Thread
	for tId, info := range subscribedThreads {
		alreadySubscribed = dbInfo.Key.String() == info.Key.String()
		if alreadySubscribed {
			bootstrapper.cfg.InitNetworkMetadataThreadId(tId)
			bootstrapper.NetworkMetadataThreadId = tId
			break
		}
	}
	// subscribe to Network Metadata Thread if necessary
	if !alreadySubscribed {
		err = client.Db.NewDBFromAddr(context.Background(), dbInfo.Addrs[0], dbInfo.Key)
		if err != nil {
			bootstrapper.logger.Printf("Error subscribing to Network Metadata Thread: %s\n", err.Error())
			return
		}
		multiaddr := dbInfo.Addrs[0].String()
		bootstrapper.NetworkMetadataThreadId = common.ThreadIdFromMultiAddr(multiaddr)
	}
	bootstrapper.logger.Printf("Obtained Network Metadata ThreadID: %s", bootstrapper.NetworkMetadataThreadId.String())

	/**
	* Register yourself as a Peer on this network.
	 */
	if !bootstrapper.IsInNodeRecords() {
		bootstrapper.addSelfToNodeRecords(false, false)
	} else {
		bootstrapper.logger.Print("Already in the NodeRecords queue")
	}
	// query for all client threads on the network
	networkThreads, err := bootstrapper.findNetworkThreads()
	if err != nil {
		bootstrapper.logger.Printf("Error finding querying Network Threads: %s\n", err.Error())
		return
	}
	for _, t := range networkThreads {
		// subscribe to each client thread
		bootstrapper.subscribeToThread(t)
	}
}

// listens for Join Network requests from new peers
func (bootstrapper *Bootstrapper) ListenAndBootstrapPeers() {
	bootstrapper.logger.Printf("Listening to Bootstrap on port %d", bootstrapper.cfg.BootstrappingCommsPort)
	bootstrapper.server = bootstrapper_comms.NewBootstrappingCommsServer(bootstrapper.cfg.ThreadDBAddr, bootstrapper.cfg.GetThreadIdentity(), bootstrapper.cfg.BootstrappingCommsPort, bootstrapper.NetworkMetadataThreadId)
	bootstrapper.server.StartServer()
}

// queries ThreadsInNetworkInfo collection to retrieve all thread DBInfo
func (bootstrapper *Bootstrapper) findNetworkThreads() ([]*common.ThreadsInNetworkSchema, error) {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return nil, err
	}

	results, err := client.Db.Find(context.Background(), bootstrapper.NetworkMetadataThreadId, common.ThreadsInNetworkSchemaName, &db.Query{}, &common.ThreadsInNetworkSchema{})
	client.Db.Close()
	if err != nil {
		bootstrapper.logger.Printf("error querying network metadata thread: %s", err)
		return nil, err
	}
	if nil == results {
		return make([]*common.ThreadsInNetworkSchema, 0), nil
	}
	threads := results.([]*common.ThreadsInNetworkSchema)
	return threads, nil
}

// finds threads this peer is subscribed to (wrapper around the ListDBs Thread DB function)
func (bootstrapper *Bootstrapper) findSubscribedThreads() (map[thread.ID]db.Info, error) {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return nil, err
	}
	return client.Db.ListDBs(context.Background())
}

// stops the bootstrapping server
func (bootstrapper *Bootstrapper) StopServer() {
	bootstrapper.server.StopServer()
}

// determine if this peer is in the NodeRecords collection
func (bootstrapper *Bootstrapper) IsInNodeRecords() bool {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return false
	}
	query := db.Where("peerId").Eq(bootstrapper.selfId.GetPublic().String())
	query.UseIndex("peerId")
	res, err := client.Db.Find(context.Background(), bootstrapper.cfg.GetNetworkMetadataThreadId(), common.NodeRecordsSchemaName, query, &common.NodeRecordsSchema{})
	if err != nil {
		bootstrapper.logger.Printf("isInNodeRecords: error querying %s", err.Error())
		return false
	}
	if nil == res {
		return false
	}
	return len(res.([]*common.NodeRecordsSchema)) > 0
}

// Create the thread and collections used to maintain peer information
func (bootstrapper *Bootstrapper) InitializeNetworkMetadata() {
	if bootstrapper.cfg.NetworkMetadataThreadId != "" {
		return
	}
	networkMetadataThreadId, err := bootstrapper.createNetworkMetadataThread()
	if err != nil {
		log.Fatalf(err.Error())
	}
	bootstrapper.cfg.InitNetworkMetadataThreadId(networkMetadataThreadId)
	log.Printf("NetId in bootstrapper: %s", bootstrapper.cfg.GetNetworkMetadataThreadId())
	bootstrapper.NetworkMetadataThreadId = networkMetadataThreadId
	if err != nil {
		bootstrapper.logger.Fatalf("error creating network metadata thread: %s", err)
	}
	reflector := jsonschema.Reflector{}
	err = bootstrapper.createCollection(common.NodeRecordsSchemaName, reflector.Reflect(&common.NodeRecordsSchema{}))
	if err != nil {
		bootstrapper.logger.Fatalf("error initializing NodeRecords Collection: %s", err)
	}
	reflector = jsonschema.Reflector{}
	err = bootstrapper.createCollection(common.NodeQueueSchemaName, reflector.Reflect(&common.NodeQueueSchema{}))
	if err != nil {
		bootstrapper.logger.Fatalf("error initializing NodeQueue Collection : %s", err)
	}
	reflector = jsonschema.Reflector{}
	err = bootstrapper.createCollection(common.NodeRecordsMetadataSchemaName, reflector.Reflect(&common.NodeRecordsMetadataSchema{}))
	if err != nil {
		bootstrapper.logger.Fatalf("error initializing NodeRecordsMetadata collection: %s", err)
	}
	reflector = jsonschema.Reflector{}
	err = bootstrapper.createCollection(common.ThreadsInNetworkSchemaName, reflector.Reflect(&common.ThreadsInNetworkSchema{}))
	if err != nil {
		bootstrapper.logger.Fatalf("error initializing ThreadsInNetwork collection: %s", err)
	}
	reflector = jsonschema.Reflector{}
	err = bootstrapper.createCollection(common.ThreadsForSaleSchemaName, reflector.Reflect(&common.ThreadsForSaleSchema{}))
	if err != nil {
		bootstrapper.logger.Fatalf("error initializing ThreadsInNetwork collection: %s", err)
	}
	reflector = jsonschema.Reflector{}
	err = bootstrapper.createCollection(common.ThreadPurchaseInfoSchemaName, reflector.Reflect(&common.ThreadPurchasesSchema{}))
	if err != nil {
		bootstrapper.logger.Fatalf("error initializing ThreadPurchases collection: %s", err)
	}
	// err = bootstrapper.addSelfToNodeQueue()
	// if err != nil {
	// 	bootstrapper.logger.Printf("error adding self to node queue: %s", err)
	// }
	err = bootstrapper.addSelfToNodeRecords(true, false)
	if err != nil {
		bootstrapper.logger.Fatalf("error adding self to node records: %s", err)
	}

}

func (bootstrapper *Bootstrapper) createCollection(name string, s *jsonschema.Schema) error {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	bootstrapper.logger.Printf("Creating NetworkMetadata Collection %s", name)
	if err != nil {
		return err
	}
	// only create index on peerId for collections with that attribute
	if name != common.NodeRecordsMetadataSchemaName && name != common.ThreadsInNetworkSchemaName && name != common.ThreadsForSaleSchemaName && name != common.ThreadPurchaseInfoSchemaName {
		err = client.Db.NewCollection(context.Background(), bootstrapper.NetworkMetadataThreadId, db.CollectionConfig{
			Name:   name,
			Schema: s,
			// create an index on the "_id" field...
			Indexes: []db.Index{{
				Path:   "peerId",
				Unique: true,
			}},
		})
	} else {
		err = client.Db.NewCollection(context.Background(), bootstrapper.NetworkMetadataThreadId, db.CollectionConfig{
			Name:   name,
			Schema: s,
		})
	}

	client.Db.Close()
	return err
}

func (bootstrapper *Bootstrapper) createNetworkMetadataThread() (thread.ID, error) {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		log.Printf("Error creating ThreadDb Client")
		return thread.ID(""), err
	}
	threadId := thread.NewIDV1(thread.Raw, 32)
	err = client.Db.NewDB(context.Background(), threadId, db.WithNewManagedName(common.NetworkMetadataThreadName))
	client.Db.Close()
	return threadId, err
}

func (bootstrapper *Bootstrapper) AddPeerToNodeRecords(peer common.NodeRecordsSchema) error {
	bootstrapper.logger.Printf("Adding peer %s to %s on network %s", peer.Id, common.NodeRecordsSchemaName, bootstrapper.cfg.NetworkMetadataThreadId)
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return err
	}
	var instances threadDB.Instances
	instances = append(instances, peer)
	_, err = client.Db.Create(context.Background(), bootstrapper.cfg.GetNetworkMetadataThreadId(), common.NodeRecordsSchemaName, instances)
	if err != nil {
		bootstrapper.logger.Printf("Error entry in NodeRecords table: %s", err.Error())
		return err
	}
	// CODE FOR listening on database events
	// events, err := client.Db.Listen(context.Background(), tId, []threadDbClient.ListenOption{{
	// 	Type: threadDbClient.ListenDelete,
	// 	Collection: common.ThreadsInNetworkInfoName,
	// }})
	// for event := range events {
	// 	event.
	// }
	client.Db.Close()
	return nil
}
func (bootstrapper *Bootstrapper) addSelfToNodeRecords(masterNode bool, inQueue bool) error {
	threadDbPort := bootstrapper.cfg.GetThreadDbPort()
	selfEntry := common.NodeRecordsSchema{
		MultiAddr:              bootstrapper.cfg.GetMultiAddress(),
		Id:                     bootstrapper.cfg.GetThreadIdentity().GetPublic().String(),
		ThreadDbPort:           threadDbPort,
		MasterNodeCommsPort:    bootstrapper.cfg.MasterNodeCommsPort,
		BootstrappingCommsPort: bootstrapper.cfg.BootstrappingCommsPort,
		InQueue:                inQueue,
		IsMasterNode:           masterNode,
		RecentlyInQueue:        false,
		// TODO TTL?
	}
	return bootstrapper.AddPeerToNodeRecords(selfEntry)
}
func (bootstrapper *Bootstrapper) addSelfToNodeQueue() error {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return err
	}
	var instances threadDB.Instances
	selfEntry := common.NodeQueueSchema{
		Id:           bootstrapper.cfg.GetThreadIdentity().GetPublic().String(),
		MultiAddr:    bootstrapper.cfg.GetMultiAddress(),
		AssignMaster: false,
		Timestamp:    time.Now().String(),
	}
	// date, error := time.Parse("2006-01-02 15:04:05", time.Now().String())

	instances = append(instances, selfEntry)
	client.Db.Create(context.Background(), bootstrapper.NetworkMetadataThreadId, common.NodeQueueSchemaName, instances)
	client.Db.Close()
	return nil
}
func (bootstrapper *Bootstrapper) subscribeToThread(info *common.ThreadsInNetworkSchema) {
	client, err := client.New(bootstrapper.threadDbAddr, bootstrapper.selfId)
	if err != nil {
		return
	}
	addr, _ := ma.NewMultiaddr(info.Addr)
	key, _ := thread.KeyFromString(info.Key)
	client.Db.NewDBFromAddr(context.Background(), addr, key)
	client.Db.Close()

}

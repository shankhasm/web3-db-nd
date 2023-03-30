package master_node

import (
	"context"
	"log"
	"math/rand"
	"strconv"
	"sync"
	"web3db/src/common"
	"web3db/src/config"
	"web3db/src/pb/peer_comms/master_node_comms"
	client "web3db/src/threaddb"

	threadDB "github.com/textileio/go-threads/api/client"

	"github.com/textileio/go-threads/core/thread"
	db "github.com/textileio/go-threads/db"

	"time"
)

var MasterNodeTimeMinutes = 1

const MaxNodeQueueSize = 5

var AllPeersPollingTimeSeconds = 2

type AllPeers struct {
	peerList []*common.NodeRecordsSchema
	numPeers int
	mtx      sync.Mutex
}

type MasterNode struct {
	NetworkMetadataThreadId thread.ID
	threadDbAddr            string
	selfId                  thread.Identity
	channel                 chan int
	server                  *master_node_comms.MasterNodeCommsServer
	cfg                     *config.AppConfig
	logger                  *log.Logger
	allPeers                *AllPeers
}

func New(channel chan int, cfg *config.AppConfig) MasterNode {
	return MasterNode{
		NetworkMetadataThreadId: cfg.GetNetworkMetadataThreadId(),
		threadDbAddr:            cfg.ThreadDBAddr,
		channel:                 channel,
		selfId:                  cfg.GetThreadIdentity(),
		cfg:                     cfg,
		logger:                  cfg.MasterNodeLogger,
		allPeers:                &AllPeers{},
	}
}

func (masterNode *MasterNode) ListenForMaintainNodeQueueAssignment() {
	masterNode.logger.Print("Listening for master node assignments")
	masterNode.server = master_node_comms.NewMasterNodeCommsServer(masterNode.cfg.ThreadDBAddr,
		masterNode.cfg.GetThreadIdentity(),
		masterNode.cfg.MasterNodeCommsPort,
		masterNode.NetworkMetadataThreadId,
		masterNode.channel)
	masterNode.server.StartServer()
}

func (masterNode *MasterNode) StopListening() {
	if nil == masterNode.server {
		masterNode.logger.Printf("MasterNodeServer Not Running.")
	}
	masterNode.server.StopServer()
}

func (masterNode *MasterNode) MaintainNodeQueueWithForceStopOption(forceStop chan bool) {
	masterNode.maintainNodeQueue(true, forceStop)
}
func (masterNode *MasterNode) MaintainNodeQueue() {
	forceStop := make(chan bool)
	masterNode.maintainNodeQueue(true, forceStop)
}
func (masterNode *MasterNode) maintainNodeQueue(flushNodeQueue bool, forceStop chan bool) {
	masterNode.logger.Print("main: Locking1...")
	masterNode.allPeers.mtx.Lock()
	masterNode.NetworkMetadataThreadId = masterNode.cfg.GetNetworkMetadataThreadId()
	masterNode.logger.Print("Starting NodeQueueMaintenance")
	if flushNodeQueue {
		err := masterNode.flushNodeQueue()
		if err != nil {
			log.Fatalf("Error flushing NodeQueue %s", err)
		}
	}

	// grab all peers except yourself
	allPeers := masterNode.findAllOtherPeers()
	masterNode.allPeers.numPeers = len(allPeers)
	peersInNodeQueue := masterNode.findNodeQueuePeers()
	numPeersInNodeQueue := len(peersInNodeQueue)
	if flushNodeQueue && numPeersInNodeQueue != 0 {
		log.Fatalf("Node Queue flush failed... still size %d", numPeersInNodeQueue)
	}
	// if there less peers on the network than MaxNodeQueueSize,
	// master node will query the peer list every 10 seconds
	masterNode.logger.Print("Ensuring there is at least one other peer on the network...")
	numPolls := 1
	for masterNode.allPeers.numPeers < 1 {
		// this query should not be long running at this point
		// masterNode.logger.Printf("#%d NodeRecords polling. %d Total Peers on the network.", numPolls, masterNode.allPeers.numPeers)
		allPeers = masterNode.findAllOtherPeers()
		masterNode.allPeers.numPeers = len(allPeers)
		time.Sleep(time.Duration(AllPeersPollingTimeSeconds) * time.Second)
		if numPolls%100 == 0 {
			AllPeersPollingTimeSeconds = AllPeersPollingTimeSeconds + 1
		}

		if AllPeersPollingTimeSeconds == 30 {
			AllPeersPollingTimeSeconds = 5
		}

		numPolls += 1
	}

	// init peer list
	masterNode.allPeers.peerList = allPeers
	masterNode.allPeers.mtx.Unlock()
	go masterNode.listenForNodeRecordsEvents()
	masterNode.logger.Printf("Enough peers available. Start filling NodeQueue with size %d", MaxNodeQueueSize)
	start := time.Now()
	for {
		select {
		case <-forceStop:
			masterNode.logger.Print("Force Stopping MaintainNodeQueue")
			return
		default:
		}
		// while the nodequeue has available spots
		masterNode.allPeers.mtx.Lock()
		for numPeersInNodeQueue < MaxNodeQueueSize {
			masterNode.allPeers.mtx.Unlock()
			// masterNode.logger.Printf("%d Peers in NodeQueue", numPeersInNodeQueue)
			// find an eligible peer
			select {
			case <-forceStop:
				masterNode.logger.Print("Force Stopping MaintainNodeQueue")

				return
			default:
			}
			targetPeer := common.NodeRecordsSchema{}
			numPeersRecentlyInQueue := 0
			masterNode.allPeers.mtx.Lock()
			for _, peer := range masterNode.allPeers.peerList {
				if peer.InQueue || peer.RecentlyInQueue || peer.IsMasterNode {
					if peer.RecentlyInQueue {
						numPeersRecentlyInQueue++
					}
					if peer.InQueue && peer.IsMasterNode {
						// master nodes are not allowed in the NodeQueue
						// something has gone wrong if this case occurs...
						masterNode.logger.Printf("Peer %s is inQueue and isMasterNode... this is illegal.", peer.Id)
					}
					continue
				} else {
					targetPeer = *peer
					break
				}
			}
			masterNode.allPeers.mtx.Unlock()
			if (common.NodeRecordsSchema{} == targetPeer) {
				// an eligible peer has not been found
				masterNode.allPeers.mtx.Lock()
				if masterNode.allPeers.numPeers != 0 && numPeersRecentlyInQueue == masterNode.allPeers.numPeers { // in case MasterNode has not yet been in the NodeQueue
					masterNode.logger.Print("Eligible peer not found")
					masterNode.logger.Print("All peers have recently been in queue. Resetting recentlyInQueue bit")
					// all peers in the network have been in the node queue
					// i.e. the round robin has completed
					err := masterNode.resetRecentlyInNodeQueue(masterNode.allPeers.peerList)
					if err != nil {
						log.Fatalf("Error resetting recentlyInNodeQueue bit: %s", err)
					}
					continue
				}
				masterNode.allPeers.mtx.Unlock()

				// No eligible peer found. wait a bit, then requery peer list and try again
				time.Sleep(time.Duration(AllPeersPollingTimeSeconds) * time.Second)
				masterNode.logger.Print("Polling NodeRecords...")
				masterNode.allPeers.mtx.Lock()
				peers := masterNode.findAllOtherPeers()
				masterNode.allPeers.peerList = peers
				masterNode.allPeers.numPeers = len(peers)
				if int(time.Since(start).Minutes()) >= MasterNodeTimeMinutes {
					masterNode.logger.Printf("Timer Expired.")
					// only assign a new master node when there's more than one peer on the network
					break
				}
				continue
			} else {
				// eligible peer has been found
				// put peer in node queue
				masterNode.logger.Printf("Elligible Peer Found. Adding %s to NodeQueue", targetPeer.Id)
				masterNode.AddPeerToNodeQueue(targetPeer)
				targetPeer.InQueue = true
				filteredPeers := make([]*common.NodeRecordsSchema, 0)
				masterNode.allPeers.mtx.Lock()
				for _, peer := range masterNode.allPeers.peerList {
					if peer.Id == targetPeer.Id {
						continue
					}
					filteredPeers = append(filteredPeers, peer)
				}
				masterNode.allPeers.peerList = filteredPeers
				masterNode.allPeers.numPeers = len(filteredPeers)
				masterNode.allPeers.mtx.Unlock()
				numPeersInNodeQueue++
			}
			masterNode.allPeers.mtx.Lock()
			if int(time.Since(start).Minutes()) >= MasterNodeTimeMinutes {
				masterNode.logger.Printf("Timer Expired.")
				// only assign a new master node when there's more than one peer on the network
				break
			}
		}

		masterNode.allPeers.mtx.Unlock()
		if int(time.Since(start).Minutes()) >= MasterNodeTimeMinutes {
			masterNode.logger.Printf("Timer Expired.")
			// only assign a new master node when there's more than one peer on the network
			break
		}

	}

	// timer has expired
	masterNode.assignNewMasterNode(forceStop)
}

func (masterNode *MasterNode) listenForNodeRecordsEvents() {
	client, _ := client.New(masterNode.threadDbAddr, masterNode.selfId)

	opts := make([]threadDB.ListenOption, 0)
	opt := threadDB.ListenOption{
		Type:       threadDB.ListenCreate,
		Collection: common.NodeRecordsSchemaName,
	}
	opts = append(opts, opt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := client.Db.Listen(ctx, masterNode.NetworkMetadataThreadId, opts)
	if err != nil {
		masterNode.logger.Print("Error Listening for Delete events on NodeRecords")
		return
	}
	for event := range events {
		// Handle event
		if event.Action.Type == threadDB.ActionCreate {
			masterNode.logger.Printf("New peer with _id: %s", event.Action.InstanceID)
			query := db.Where("_id").Eq(event.Action.InstanceID)
			res, _ := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, query, &common.NodeRecordsSchema{})
			if nil == res {
				continue
			}
			peers := res.([]*common.NodeRecordsSchema)
			if len(peers) == 0 {
				continue
			}
			newPeer := peers[0]
			masterNode.allPeers.mtx.Lock()
			masterNode.allPeers.peerList = append(masterNode.allPeers.peerList, newPeer)
			masterNode.allPeers.mtx.Unlock()
		}
	}
}

func (masterNode *MasterNode) assignNewMasterNode(forceStop chan bool) {
	masterNode.logger.Print("Assigning New MasterNode")
	peers := masterNode.findAllOtherPeers()
	candidates := make([]*common.NodeRecordsSchema, 0)
	for _, peer := range peers {
		if !peer.InQueue {
			candidates = append(candidates, peer)
		}
	}
	// arbitrarily pick a new master node for now
	for {
		select {
		case <-forceStop:
			masterNode.logger.Print("Force Stopping MaintainNodeQueue")
			return
		default:
		}
		rand.Seed(time.Now().Unix())
		if len(candidates) == 0 {

			// try to pull from NodeQueue
			client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
			if err != nil {
				log.Printf("Error creating ThreadDB client: %s", err)
				return
			}
			res, err := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeQueueSchemaName, &db.Query{}, &common.NodeQueueSchema{})
			if err != nil || res == nil {
				log.Printf("Error querying NodeQueue: %s", err)
				return
			}
			nodeQueuePeers := res.([]*common.NodeQueueSchema)
			if len(nodeQueuePeers) == 0 {

				// some recursion here.
				// Base Case: length(candidates) != 0, i.e. there is at least one candidate for master node
				// Recursive Casle: length(candidates) == 0, i.e. no candidates
				// if there are no candidates, keep maintaining the node queue
				masterNode.logger.Printf("No Candidates left to choose from. Recursive Call to MaintainNodeQueue")
				masterNode.maintainNodeQueue(true, forceStop)
				return
			}
			// arbitrarily choose a peer in the NodeQueue
			rand.Seed(time.Now().Unix())
			candidate := nodeQueuePeers[rand.Intn(len(nodeQueuePeers))]
			pickMe, _ := masterNode.findPeerById(candidate.Id)
			if pickMe != nil {
				candidates = append(candidates, pickMe)
			} else {
				masterNode.maintainNodeQueue(true, forceStop)
				return
			}

		}

		i := rand.Intn(len(candidates))
		newMasterNode := candidates[i]
		// transmit assign message

		addr := common.IpAddrFromMultiAddr(newMasterNode.MultiAddr) + ":" + strconv.Itoa(newMasterNode.MasterNodeCommsPort)
		log.Printf("Candidate Found. Sending AssignMasterNode request to %s", addr)

		comms := master_node_comms.NewMasterNodeCommsClient(addr)
		if comms == nil || // error initiating client
			comms.AssignNewMasterNode() != nil { // error sending request

			masterNode.logger.Printf("Error Contacting %s:  \nfinding another Candidate", addr)

			candidates[i] = candidates[len(candidates)-1]
			candidates = candidates[:len(candidates)-1]
			continue
		}
		err := masterNode.updateMasterNode(*newMasterNode)
		if err != nil {
			log.Fatalf("Error updating new master node info: %s", err)
		}
		masterNode.logger.Printf("Assigned %s as new Master Node", newMasterNode.Id)
		break
	}

	masterNode.updateSelfMasterNodeStatusFalse()
	masterNode.logger.Print("Sending StopNodeQueueMaintenance Signal to MasterNode channel")
	masterNode.channel <- common.StopNodeQueueMaintenance

}

func (masterNode *MasterNode) findAllOtherPeers() []*common.NodeRecordsSchema {

	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return nil
	}

	query := db.Where("peerId").Ne(masterNode.cfg.GetThreadIdentity().GetPublic().String())
	query.UseIndex("peerId")
	// startTime := time.Now()
	// masterNode.logger.Printf("MasterNode.findAllPeers: finding all peers on the network %s", masterNode.NetworkMetadataThreadId)
	results, err := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, query, &common.NodeRecordsSchema{})
	// masterNode.logger.Printf("MasterNode.findAllPeers: took %f seconds to find all peers on the network", time.Since(startTime).Seconds())
	client.Db.Close()
	if err != nil {
		masterNode.logger.Printf("error querying network metadata thread: %s", err)
		return make([]*common.NodeRecordsSchema, 0)
	}
	threads := results.([]*common.NodeRecordsSchema)
	return threads
}

func (masterNode *MasterNode) findNodeQueuePeers() []*common.NodeQueueSchema {
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return make([]*common.NodeQueueSchema, 0)
	}

	results, err := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeQueueSchemaName, &db.Query{}, &common.NodeQueueSchema{})
	client.Db.Close()
	if err != nil {
		masterNode.logger.Printf("error querying network metadata thread: %s", err)
	}
	if results == nil {
		return make([]*common.NodeQueueSchema, 0)
	}
	peers := results.([]*common.NodeQueueSchema)
	return peers
}

func (masterNode *MasterNode) flushNodeQueue() error {
	masterNode.logger.Printf("Flushing NodeQueue")
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return err
	}
	nodeQueue := masterNode.findNodeQueuePeers()

	var query *db.Query
	for _, deleteMe := range nodeQueue {
		if query == nil {
			query = db.Where("peerId").Eq(deleteMe.Id)
		} else {
			query = query.Or(db.Where("peerId").Eq(deleteMe.Id))
		}
		log.Printf("Delete peer %s", deleteMe.ThreadDbId)
		err = client.Db.Delete(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeQueueSchemaName, []string{deleteMe.ThreadDbId})
		if err != nil {
			log.Fatalf("Error deleting instances from NodeQueue %s", err)
			return err
		}

	}
	if query == nil {
		query = &db.Query{}
	}
	nodeQueue = masterNode.findNodeQueuePeers()
	if len(nodeQueue) != 0 {
		log.Fatalf("Early Fail")
	}
	query.UseIndex("peerId")
	peersInNodeQueue, err := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, query, &common.NodeRecordsSchema{})
	if err != nil {
		log.Fatalf("Error finding NodeRecords in NodeQueue %s", err)
		return err
	}
	for _, peer := range peersInNodeQueue.([]*common.NodeRecordsSchema) {
		log.Printf("Updating %s recentlyInNodeQueue bit to true", peer.Id)
		peer.RecentlyInQueue = true
		peer.InQueue = false
		err = client.Db.Save(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, threadDB.Instances{peer})
		if err != nil {
			log.Fatalf("Error updating NodeRecords %s", err)
			return err
		}
	}
	client.Db.Close()
	return nil
}

func (masterNode *MasterNode) AddPeerToNodeQueue(peer common.NodeRecordsSchema) error {
	masterNode.logger.Printf("Adding %s to NodeQueue", peer.Id)
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return err
	}
	_, err = client.Db.Create(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeQueueSchemaName, threadDB.Instances{common.NodeQueueSchema{
		Id:           peer.Id,
		MultiAddr:    peer.MultiAddr, // thread db multiaddress
		AssignMaster: false,
		ThreadDbPort: peer.ThreadDbPort,
		Timestamp:    time.Now().GoString(),
	}})
	if err != nil {
		masterNode.logger.Printf("Error Adding %s to NodeQueue: %s", peer.Id, err)
		return err
	}

	peer.InQueue = true
	err = client.Db.Save(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, threadDB.Instances{peer})
	if err != nil {
		masterNode.logger.Printf("Error Updating %s NodeRecord entry: %s", peer.Id, err)
		return err
	}
	return nil
}

func (masterNode *MasterNode) updateSelfMasterNodeStatusFalse() error {
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return err
	}
	query := db.Where("peerId").Eq(masterNode.selfId.GetPublic().String())
	res, err := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, query, &common.NodeRecordsSchema{})
	me := res.([]*common.NodeRecordsSchema)
	if err != nil {
		log.Printf("Error finding NodeRecords in NodeQueue %s", err)
		return err
	}
	if len(me) != 1 {
		log.Printf("Should only be one self record in NodeRecords")
	}
	me[0].IsMasterNode = false
	err = client.Db.Save(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, threadDB.Instances{me[0]})
	return err
}

func (masterNode *MasterNode) updateMasterNode(newMasterNode common.NodeRecordsSchema) error {
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return err
	}
	newMasterNode.IsMasterNode = true
	err = client.Db.Save(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, threadDB.Instances{newMasterNode})
	return err
}

func (masterNode *MasterNode) findPeerById(id string) (*common.NodeRecordsSchema, error) {
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return nil, err
	}
	query := db.Where("peerId").Eq(id)
	query.UseIndex("peerId")
	res, err := client.Db.Find(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, query, &common.NodeRecordsSchema{})
	if err != nil {
		masterNode.logger.Printf("findPeerById: error querying NodeRecords %s", err)
		return nil, err
	}
	if res == nil {
		return &common.NodeRecordsSchema{}, nil
	}
	candidates := res.([]*common.NodeRecordsSchema)
	if len(candidates) == 0 {
		return nil, nil
	}
	rand.Seed(time.Now().Unix())
	candidate := candidates[rand.Intn(len(candidates))]
	return candidate, nil

}

func (masterNode *MasterNode) resetRecentlyInNodeQueue(peers []*common.NodeRecordsSchema) error {
	client, err := client.New(masterNode.threadDbAddr, masterNode.selfId)
	if err != nil {
		masterNode.logger.Printf("Error creating client: %s\n", err.Error())
		return err
	}
	for _, peer := range peers {
		peer.RecentlyInQueue = false
	}
	for _, peer := range peers {
		err = client.Db.Save(context.Background(), masterNode.NetworkMetadataThreadId, common.NodeRecordsSchemaName, threadDB.Instances{peer})
	}
	return err
}

func CoordinateMasterNode(masterNode *MasterNode, channel chan int) {
	log.Print("Waiting for MasterNode signal...")
	masterNode.logger.Print("Waiting for MasterNode signal...")
	go masterNode.ListenForMaintainNodeQueueAssignment()
	signal := <-channel

	for {
		if signal == common.StartNodeQueueMaintenance {
			log.Print("StartNodeQueueMaintenance Signal recieved")
			masterNode.logger.Print("StartNodeQueueMaintenance Signal recieved")
			masterNode.StopListening()
			go masterNode.MaintainNodeQueue()
			masterNode.logger.Print("Waiting for MasterNode signal...")
			log.Print("Waiting for MasterNode signal...")
			signal = <-channel
		} else if signal == common.StopNodeQueueMaintenance {
			masterNode.logger.Print("StopNodeQueueMaintenance Signal recieved")
			log.Print("StopNodeQueueMaintenance Signal recieved")

			// wait to be assigned the master node
			go masterNode.ListenForMaintainNodeQueueAssignment()
			masterNode.logger.Print("Waiting for MasterNode signal...")
			log.Print("Waiting for MasterNode signal...")

			signal = <-channel
		}
	}
}

func CoordinateMasterNodeWithForceStopOption(masterNode *MasterNode, channel chan int, forceStop chan bool) {
	masterNode.logger.Print("Waiting for MasterNode signal...")
	signal := <-channel
	for {
		if signal == common.StartNodeQueueMaintenance {
			masterNode.logger.Print("StartNodeQueueMaintenance Signal recieved")
			masterNode.StopListening()
			go masterNode.MaintainNodeQueueWithForceStopOption(forceStop)
			masterNode.logger.Print("Waiting for MasterNode signal...")
			signal = <-channel
		} else if signal == common.StopNodeQueueMaintenance {
			masterNode.logger.Print("StopNodeQueueMaintenance Signal recieved")
			// wait to be assigned the master node
			go masterNode.ListenForMaintainNodeQueueAssignment()
			masterNode.logger.Print("Waiting for MasterNode signal...")
			signal = <-channel
		}
	}
}

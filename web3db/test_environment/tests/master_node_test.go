package tests

import (
	"context"
	"log"
	"strconv"
	"testing"
	"time"
	"web3db/src/common"
	"web3db/src/master_node"
	"web3db/src/pb/peer_comms/master_node_comms"
	"web3db/test_environment"

	"github.com/textileio/go-threads/db"
)

func TestAssignNewMasterNode(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()

	go master_node.CoordinateMasterNode(&environment.MasterNode, environment.MasterNodeChannel)

	time.Sleep(10 * time.Second)
	addr := environment.Config.LocalIpAddr + ":" + strconv.Itoa(environment.Config.MasterNodeCommsPort)
	log.Printf("Sending AssignMasterNode request to %s", addr)

	comms := master_node_comms.NewMasterNodeCommsClient(addr)
	err := comms.AssignNewMasterNode()
	if err != nil {
		log.Fatalf("%s", err)
	}
	time.Sleep(10 * time.Minute)

}
func TestMasterNodeStartStopServer(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
	go environment.MasterNode.ListenForMaintainNodeQueueAssignment()
	time.Sleep(2 * time.Second)
	environment.MasterNode.StopListening()

}

func TestMaintainNodeQueue(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
	go environment.MasterNode.MaintainNodeQueue()
	time.Sleep(1 * time.Second)
	go environment.SimulatePeersJoining(10)
	time.Sleep(3 * time.Minute)
}

func TestCoordinateMasterNode(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()

	// force stop MaintainNodeQueue maintenance
	// this is necessary since all simulated peers in network
	// are fake.
	// MaintainNodeQueue normally
	// terminates on it's own after successfully sending an "AssignMasterNodeRequest".

	// forceStopMaintainNodeQueue simulates a "successful exit" to MaintainNodeQueue
	forceStopMaintainNodeQueue := make(chan bool)

	// forceStop is a duplicate for thread safety
	go environment.MasterNode.MaintainNodeQueueWithForceStopOption(forceStopMaintainNodeQueue)
	time.Sleep(1 * time.Second)
	environment.SimulatePeersJoining(10)
	log.Print("Begin CoordinateMasterNode")
	go master_node.CoordinateMasterNodeWithForceStopOption(&environment.MasterNode, environment.MasterNodeChannel, forceStopMaintainNodeQueue)
	time.Sleep(10 * time.Second)
	go SanityCheckNodeQueue(&environment, 60)
	i := 1
	for i <= 2 {
		log.Printf("Sending ForceStop and StopNodeQueueMaintenance Signal #%d", i)

		forceStopMaintainNodeQueue <- true
		environment.MasterNodeChannel <- common.StopNodeQueueMaintenance

		time.Sleep(30 * time.Second)
		log.Printf("Sending StartNodeQueueMaintenance Signal #%d", i)
		environment.MasterNodeChannel <- common.StartNodeQueueMaintenance
		time.Sleep(30 * time.Second)
		i++
	}
	time.Sleep(1 * time.Minute)
}

func SanityCheckNodeQueue(env *test_environment.TestEnvironment, pollingTimeSeconds int) {
	pollingTime := time.Duration(pollingTimeSeconds) * time.Second
	for {
		nq, _ := env.ThreadDBClient.Db.Find(context.Background(), env.Config.GetNetworkMetadataThreadId(), common.NodeQueueSchemaName, &db.Query{}, &common.NodeQueueSchema{})
		if nq == nil {
			nq = make([]interface{}, 0)
		}
		nodeQueue := nq.([]*common.NodeQueueSchema)
		lengthNodeQueue := len(nodeQueue)

		p, _ := env.ThreadDBClient.Db.Find(context.Background(), env.Config.GetNetworkMetadataThreadId(), common.NodeRecordsSchemaName, &db.Query{}, &common.NodeRecordsSchema{})
		if p == nil {
			log.Fatalf("Empty NodeRecords")
		}
		peers := p.([]*common.NodeRecordsSchema)
		lengthPeers := len(peers)

		if lengthNodeQueue > master_node.MaxNodeQueueSize { // if NodeQueue overflown
			log.Fatalf("NodeQueue overflown")

		} else if lengthNodeQueue == 0 && lengthPeers > 1 { // nodeQueue empty and more than 1 peer on the network
			log.Fatalf("nodeQueue empty and more than 1 peer on the network")
		} else if lengthNodeQueue < master_node.MaxNodeQueueSize && // less peers in node queue than max size
			lengthPeers > master_node.MaxNodeQueueSize+1 { // and there are enough peers to fill the node queue to the max size
			log.Fatalf("less peers in node queue (%d) than max size (%d) and there are enough peers in nodeRecords (%d) to fill the node queue to the max size", lengthNodeQueue, master_node.MaxNodeQueueSize, lengthPeers)
		}
		time.Sleep(pollingTime)
	}

}

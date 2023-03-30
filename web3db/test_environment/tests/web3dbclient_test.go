package tests

import (
	"crypto/rand"
	"log"
	"testing"
	"time"
	"web3db/src/master_node"
	"web3db/src/web3db"
	"web3db/test_environment"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/textileio/go-threads/core/thread"
)

func TestResolveRequest(t *testing.T) {
	environment := test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
	log.Printf("net met tID: %s", environment.Config.GetNetworkMetadataThreadId().String())

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
	go master_node.CoordinateMasterNodeWithForceStopOption(&environment.MasterNode, environment.MasterNodeChannel, forceStopMaintainNodeQueue)
	time.Sleep(10 * time.Second)
	i := 1
	for i <= 7 {
		privateKey, _, err := crypto.GenerateEd25519Key(rand.Reader) // Private key is kept locally
		if err != nil {
			log.Fatalf("Errow while generating peer Ed25519 key. %v\n", err)
			return
		}
		tId := thread.NewLibp2pIdentity(privateKey)
		client := web3db.NewClient(tId.GetPublic().String(),
			environment.Config.ThreadDBAddr,
			environment.Config.GetThreadIdentity(),
			environment.Config.GetNetworkMetadataThreadId())
		log.Printf("net met tID: %s", environment.Config.GetNetworkMetadataThreadId().String())
		log.Printf("Client Thread DB Address after ResolveRequest: %s", client.ThreadDBAddr)
		i++
	}
}

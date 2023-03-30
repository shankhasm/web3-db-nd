package tests

import (
	"crypto/rand"
	"fmt"
	"log"
	"testing"
	"time"
	"web3db/src/config"
	"web3db/src/master_node"
	"web3db/src/web3db"
	webserv "web3db/src/web_server"
	"web3db/test_environment"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/textileio/go-threads/core/thread"
)

const TestTimeMinutes = 30

const MaxNetworkSize = 30

func TestSampleNetwork(t *testing.T) {
	i := 1
	for i <= MaxNetworkSize {
		log.Printf("======== Testing Sample Network of %d additional peers", i)

		if i != 1 {
			// give some cool down time
			time.Sleep(30 * time.Second)
		}
		go testSampleNetwork(i)
		i++
	}
}
func TestTwoNodeSampleNetwork(t *testing.T) {
	// optionally use admin portal to inspect internal states
	//
	// testSampleNetwork(2)
	go testSampleNetwork(1)
}

func TestThreeNodeSampleNetwork(t *testing.T) {
	// optionally use admin portal to inspect internal states
	//
	// testSampleNetwork(2)
	go testSampleNetwork(2)
}

func TestFourNodeSampleNetwork(t *testing.T) {
	go testSampleNetwork(3)
}
func testSampleNetwork(numPeers int) {
	env := test_environment.NewTestEnvironment("config.test.yaml")
	env.Setup()
	defer env.TearDown()

	go env.Bootstrapper.ListenAndBootstrapPeers()
	forceStop := make(chan bool)
	go env.MasterNode.MaintainNodeQueueWithForceStopOption(forceStop)
	master_node.MasterNodeTimeMinutes = 1
	go master_node.CoordinateMasterNodeWithForceStopOption(&env.MasterNode, env.MasterNodeChannel, forceStop)

	serv := webserv.New(env.Config)
	// go env.SimulateMassDataInsert(1, 1, 2000)
	go serv.Start()

	i := 0
	bootstrapperPort := 1999
	masterNodePort := 3005
	max := numPeers
	for i < max {
		time.Sleep(2 * time.Second)
		if i == 0 {
			go simulatePeer(bootstrapperPort, masterNodePort, i, 5001, env.Config.NetworkMetadataThreadId)
			i++
			continue
		} else if i == 10 {
			go simulatePeer(bootstrapperPort+i, masterNodePort+i, i, bootstrapperPort+i-1, env.Config.NetworkMetadataThreadId)
			go SanityCheckNodeQueue(&env, 60)
			i++
			continue
		}
		go simulatePeer(bootstrapperPort+i, masterNodePort+i, i, bootstrapperPort+i-1, env.Config.NetworkMetadataThreadId)
		i++
	}

	time.Sleep(30 * time.Minute)
	log.Print("Force Stopping...")
	forceStop <- true
	time.Sleep(30 * time.Second)
}
func simulatePeer(bootstrapperCommsPort int, masterNodePort int, peerNum int, bootStrapperMultiAddrPort int, networkMetadata string) {
	dummyConfig := config.AppConfig{
		ThreadDBAddr:            "127.0.0.1:6006",
		BootstrapperMultiaddr:   fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", bootStrapperMultiAddrPort),
		LogDirectory:            "",
		BootstrappingCommsPort:  bootstrapperCommsPort,
		MasterNodeCommsPort:     masterNodePort,
		Path:                    "",
		LocalIpAddr:             "127.0.0.1",
		NetworkMetadataThreadId: "",
	}
	dummyConfig.InitEccIdentity()
	dummyConfig.LogDirectory = fmt.Sprintf("./logs/peer_%s/", dummyConfig.GetThreadIdentity().GetPublic().String())
	dummyConfig.InitLoggers()
	dummyEnv := test_environment.NewTestEnvironmentWithConfig(&dummyConfig)
	dummyEnv.Bootstrapper.JoinNetwork()
	go dummyEnv.Bootstrapper.ListenAndBootstrapPeers()
	master_node.CoordinateMasterNode(&dummyEnv.MasterNode, dummyEnv.MasterNodeChannel)
}

func TestResolveRequest1(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
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

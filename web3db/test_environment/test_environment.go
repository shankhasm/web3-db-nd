package test_environment

import (
	"context"
	cryptoRand "crypto/rand"
	b64 "encoding/base64"
	"log"
	"math/rand"
	"os"
	"time"
	"web3db/src/bootstrapper"
	"web3db/src/common"
	"web3db/src/config"
	"web3db/src/master_node"
	client "web3db/src/threaddb"

	"github.com/alecthomas/jsonschema"
	"github.com/libp2p/go-libp2p-core/crypto"
	threadDb "github.com/textileio/go-threads/api/client"
	"github.com/textileio/go-threads/core/thread"
	"github.com/textileio/go-threads/db"
)

// the queue of peers ready to accept database requests from clients
type TestSchema struct {
	ThreadDbId string `json:"_id"`
	PeerId     string `json:"peerId"`
	Foo        string `json:"foo"`
	Bar        string `json:"bar"`
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

const TestSchemaName = "fooBarBaz"

type TestEnvironment struct {
	ThreadDBClient    client.ThreadDBClient
	Bootstrapper      bootstrapper.Bootstrapper
	MasterNode        master_node.MasterNode
	MasterNodeChannel chan int
	Config            *config.AppConfig
}

func NewTestEnvironment(config_path string) TestEnvironment {
	cfg := config.New(config_path)

	c, _ := client.New(cfg.ThreadDBAddr, cfg.GetThreadIdentity())
	masterNodeChannel := make(chan int)
	return TestEnvironment{
		ThreadDBClient:    c,
		Bootstrapper:      bootstrapper.New(&cfg),
		MasterNodeChannel: masterNodeChannel,
		MasterNode:        master_node.New(masterNodeChannel, &cfg),
		Config:            &cfg,
	}
}

func NewTestEnvironmentWithConfig(cfg *config.AppConfig) TestEnvironment {
	c, _ := client.New(cfg.ThreadDBAddr, cfg.GetThreadIdentity())
	masterNodeChannel := make(chan int)
	return TestEnvironment{
		ThreadDBClient:    c,
		Bootstrapper:      bootstrapper.New(cfg),
		MasterNodeChannel: masterNodeChannel,
		MasterNode:        master_node.New(masterNodeChannel, cfg),
		Config:            cfg,
	}
}
func (env *TestEnvironment) Setup() {
	env.Bootstrapper.InitializeNetworkMetadata()
}

func (env *TestEnvironment) TearDown() {
	res, _ := env.ThreadDBClient.Db.ListDBs(context.Background())
	printListDBs(res)
	for id, _ := range res {
		// Remove Network Metadata Thread
		//if info.Name == common.NetworkMetadataThreadName {
		env.ThreadDBClient.Db.DeleteDB(context.Background(), id)
		//}
	}
	env.ThreadDBClient.Db.Close()
	env.Config.NetworkMetadataThreadId = ""
	env.Config.Save()
	os.RemoveAll(env.Config.LogDirectory)

	os.Remove(env.Config.LogDirectory + config.MasterNodeLogFileName)
	os.Remove(env.Config.LogDirectory + config.BootstrapperLogFileName)
	os.Remove(env.Config.LogDirectory + config.AdminLogFileName)

}

func (env *TestEnvironment) SimulateMassDataInsert(numThreads int, numCollectionsPerThread int, numInstancesPerCollection int) {
	/*
	* Initialize logger
	 */
	file, err := os.OpenFile("simulateMassDataInsertTest.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	log := log.New(file, "", log.LstdFlags)
	reflector := jsonschema.Reflector{}
	schema := reflector.Reflect(TestSchema{})
	createdThreads := make([]thread.ID, 0)
	i := 0
	for i < numThreads {
		tID := env.Config.GetNetworkMetadataThreadId() //thread.NewIDV1(thread.Raw, 32)
		createdThreads = append(createdThreads, tID)
		env.ThreadDBClient.Db.NewDB(context.Background(), tID)
		log.Printf("===========================Created Thread %s===========================", tID)
		j := 0
		numTxns := 0
		for j < numCollectionsPerThread {
			schemaName := TestSchemaName + RandStringRunes(6)
			log.Printf("===========================Created Collection %s in thread %s===========================", schemaName, tID)
			env.ThreadDBClient.Db.NewCollection(context.Background(), tID, db.CollectionConfig{
				Name:   schemaName,
				Schema: schema,
			})
			q := 0
			for q < 4 {
				l := 0
				ids := make([]string, 0)
				log.Print("===========================Creating Instances===========================")
				for l < numInstancesPerCollection {
					k := 0
					batchSize := 2000
					testData := make(threadDb.Instances, 0)
					for k < batchSize {
						fake := &TestSchema{
							PeerId: RandStringRunes(3),
							Foo:    RandStringRunes(4),
							Bar:    RandStringRunes(5),
						}
						testData = append(testData, fake)
						k++
					}
					res, err := env.ThreadDBClient.Db.Create(context.Background(), tID, schemaName, testData)
					if err != nil {
						log.Fatal(err)
					}
					numTxns++
					ids = append(ids, res...)
					start := time.Now()
					env.ThreadDBClient.Db.Find(context.Background(), tID, schemaName, &db.Query{}, &TestSchema{})
					duration := time.Since(start).Milliseconds()

					l += batchSize
					// number of Transactions, time in milliseconds to query all instances in collection, numRecordsInserted
					log.Printf("%d, %d, %d", numTxns, duration, l)
				}
				l = 0
				log.Print("===========================Deleting Instances===========================")
				for l < numInstancesPerCollection {
					batchSize := 1000
					if len(ids) < batchSize {
						break
					}
					err := env.ThreadDBClient.Db.Delete(context.Background(), tID, schemaName, ids[:batchSize])
					if err != nil {
						log.Fatal()
					}
					ids = ids[batchSize+1:]
					numTxns++

					start := time.Now()
					env.ThreadDBClient.Db.Find(context.Background(), tID, schemaName, &db.Query{}, &TestSchema{})
					duration := time.Since(start).Milliseconds()

					l += batchSize
					// number of Transactions, time in milliseconds to query all instances in collection, numRecords in collection
					log.Printf("%d, %d, %d", numTxns, duration, numInstancesPerCollection-l)
				}
				q++
			}
			j++
		}
		i++
	}
}

func (env *TestEnvironment) SimulatePeersJoining(numPeers int) {
	log.Printf("Simulating Peers Joining Network...")
	i := 0
	for i < numPeers {
		privateKey, _, err := crypto.GenerateEd25519Key(cryptoRand.Reader) // Private key is kept locally
		if err != nil {
			log.Fatalf("Error while generating peer Ed25519 key. %v\n", err)
			return
		}
		bytes, err := crypto.MarshalPrivateKey(privateKey)
		if err != nil {
			log.Fatalf("Error retrieving Ed25519 peer key bytes. %v\n", err)
			return
		}
		id := b64.StdEncoding.EncodeToString(bytes)
		peer := common.NodeRecordsSchema{
			Id:                     config.UnmarshalPrivateKey(id).GetPublic().String(),
			MultiAddr:              env.Config.GetMultiAddress(),
			ThreadDbPort:           env.Config.GetThreadDbPort(),
			MasterNodeCommsPort:    env.Config.MasterNodeCommsPort,
			BootstrappingCommsPort: env.Config.BootstrappingCommsPort,
			IsMasterNode:           false,
			RecentlyInQueue:        false,
			InQueue:                false,
		}
		env.Bootstrapper.AddPeerToNodeRecords(peer)
		i++
	}
}

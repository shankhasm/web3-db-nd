package tests

import (
	"log"
	"testing"
	"time"
	"web3db/test_environment"
)

func TestJoinNetwork(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
	go environment.Bootstrapper.ListenAndBootstrapPeers()
	time.Sleep(2 * time.Second)
	i := 0
	for i < 4 {
		environment.Bootstrapper.JoinNetwork()
		i++
	}

	if !environment.Bootstrapper.IsInNodeRecords() {
		log.Fatal("Not In NodeRecords")
	}
	environment.Bootstrapper.StopServer()

}

func TestStartStopServer(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
	go environment.Bootstrapper.ListenAndBootstrapPeers()
	time.Sleep(2 * time.Second)
	environment.Bootstrapper.StopServer()
}

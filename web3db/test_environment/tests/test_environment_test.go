package tests

import (
	"testing"
	"web3db/test_environment"
)

var environment test_environment.TestEnvironment

func TestSetupTearDown(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
}

func TestTearDown(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.TearDown()
}

func TestSimulateMassDataInsert(t *testing.T) {
	environment = test_environment.NewTestEnvironment("./config.test.yaml")
	environment.Setup()
	defer environment.TearDown()
	environment.SimulateMassDataInsert(1, 5, 10000000)
}

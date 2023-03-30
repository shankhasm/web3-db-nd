package tests

import (
	"testing"
	"web3db/src/config"
)

func TestGetLocalIpAddress(t *testing.T) {
	// log.Printf("local ip address: %s", ip)
}

func TestLoadSave(t *testing.T) {
	c := config.AppConfig{}
	c.WithFile("config.test.yaml").Load()
	c.Save()
}

func TestInitLoggers(t *testing.T) {
	c := config.AppConfig{}
	c.WithFile("config.test.yaml")
	c.Load()
	c.InitLoggers()
}

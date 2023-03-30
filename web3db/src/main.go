package main

import (
	"web3db/src/bootstrapper"
	"web3db/src/common"
	"web3db/src/config"
	"web3db/src/master_node"
	webserv "web3db/src/web_server"
)

// global config
var cfg config.AppConfig

var channels map[string](chan int)

func main() {

	cfg = config.New("./config.yaml")

	launchWeb3DBNode()

}

func launchWeb3DBNode() {
	startingNewNetwork := cfg.BootstrapperMultiaddr == ""
	bootstrapper := bootstrapper.New(&cfg)
	masterNode := master_node.New(channels[common.MasterNodeChannel], &cfg)

	if startingNewNetwork {
		bootstrapper.InitializeNetworkMetadata()
		go masterNode.MaintainNodeQueue()
	} else {
		bootstrapper.JoinNetwork()
	}
	go bootstrapper.ListenAndBootstrapPeers()
	go master_node.CoordinateMasterNode(&masterNode, channels[common.MasterNodeChannel])

	listenForApiRequests()
}

func launchWeb3DBPeer() {

}

func listenForApiRequests() {
	webServ := webserv.New(&cfg)

	// start web server
	webServ.Start()
}

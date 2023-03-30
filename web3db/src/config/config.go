package config

import (
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	externalip "github.com/glendc/go-external-ip"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/textileio/go-threads/core/thread"
	"gopkg.in/yaml.v2"
)

const MasterNodeLogFileName = "masterNodeLogs"
const BootstrapperLogFileName = "bootstrapperLogs"
const AdminLogFileName = "adminLogs"

// config.yaml structure
type ConfigFile struct {
	HttpsPort               int    `yaml:"https_port"`
	HttpPort                int    `yaml:"http_port"`
	ThreadDBAddr            string `yaml:"threaddb_addr"`
	TLSCertPath             string `yaml:"tls_cert_path"`
	TLSPrivKeyPath          string `yaml:"tls_pk_path"`
	Identity                string `yaml:"private_key"`
	BootstrapMultiaddr      string `yaml:"bootstrap_multiaddr"`
	BootstrappingCommsPort  int    `yaml:"bootstrap_comms_port"`
	MasterNodeCommsPort     int    `yaml:"master_node_comms_port"`
	DevMode                 bool   `yaml:"dev_mode"`
	NetworkMetadataThreadId string `yaml:"network_metadata_thread_id"`
	LogDirectory            string `yaml:"log_directory"`
	LocalIpAddr             string `yaml:"local_ip_addr"`
}

type AppConfig struct {
	HttpsPort               int    `yaml:"https_port"`
	HttpPort                int    `yaml:"http_port"`
	ThreadDBAddr            string `yaml:"threaddb_addr"`
	TLSCertPath             string `yaml:"tls_cert_path"`
	TLSPrivKeyPath          string `yaml:"tls_pk_path"`
	Identity                string `yaml:"private_key"`
	BootstrapperMultiaddr   string `yaml:"bootstrap_multiaddr"`
	BootstrappingCommsPort  int    `yaml:"bootstrap_comms_port"`
	MasterNodeCommsPort     int    `yaml:"master_node_comms_port"`
	DevMode                 bool   `yaml:"dev_mode"`
	NetworkMetadataThreadId string `yaml:"network_metadata_thread_id"`
	LogDirectory            string `yaml:"log_directory"`
	LocalIpAddr             string `yaml:"local_ip_addr"`
	AdminLogger             *log.Logger
	BootstrapperLogger      *log.Logger
	MasterNodeLogger        *log.Logger
	Path                    string
}

const ORG_METADATA_THREAD = "_organization_metadata"
const API_KEY_STORAGE_COLLECTION = "api_keys"

// var CfgInstance = Config{}

func New(path string) AppConfig {
	cfg := AppConfig{}
	cfg.WithFile(path).init()
	return cfg
}
func (cfg *AppConfig) WithFile(path string) *AppConfig {
	if _, err := os.Stat(path); err == nil {
		cfg.Path = path
	} else if errors.Is(err, os.ErrNotExist) {
		log.Fatalf("File %s does not exist.", path)
	}
	return cfg
}
func (cfg *AppConfig) init() {
	cfg.Load()
	if cfg.Identity == "" {
		cfg.InitEccIdentity()
	}

	var cert string = ""
	var pk string = ""
	var err error

	if cfg.TLSCertPath != "" && cfg.TLSPrivKeyPath != "" {
		cert, err = filepath.Abs(cfg.TLSCertPath)
		if err != nil {
			log.Fatal("invalid tls certificate filepath")
		}
		pk, err = filepath.Abs(cfg.TLSPrivKeyPath)
		if err != nil {
			log.Fatal("invalid tls private key filepath")
		}
	}
	cfg.TLSCertPath = cert
	cfg.TLSPrivKeyPath = pk

	cfg.InitLoggers()

	cfg.Save()

}

func (cfg *AppConfig) InitLoggers() {
	if cfg.LogDirectory == "" {
		logger := log.Default()
		cfg.AdminLogger = logger
		cfg.BootstrapperLogger = logger
		cfg.MasterNodeLogger = logger
		return
	}
	if _, err := os.Stat(cfg.LogDirectory); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(cfg.LogDirectory, os.ModePerm)
		if err != nil {
			log.Fatalf("Error making log directory: %s", err)
		}
	}
	adminLogFileName := cfg.LogDirectory + AdminLogFileName
	bootStrapperLogFileName := cfg.LogDirectory + BootstrapperLogFileName
	masterNodeLogFileName := cfg.LogDirectory + MasterNodeLogFileName
	/*
	* Initialize logger
	 */
	file, err := os.OpenFile(adminLogFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger := log.New(file, "AdminLogs", log.LstdFlags)
	cfg.AdminLogger = logger
	file, err = os.OpenFile(bootStrapperLogFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(file, "BootstrapperLogs", log.LstdFlags)
	cfg.BootstrapperLogger = logger
	file, err = os.OpenFile(masterNodeLogFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(file, "MasterNodeLogs", log.LstdFlags)
	cfg.MasterNodeLogger = logger
}

func (cfg *AppConfig) GetMultiAddress() string {
	return "/ip4/" + cfg.getLocalIp() + "/tcp/" + fmt.Sprint(cfg.BootstrappingCommsPort) + "/"
}
func (cfg *AppConfig) GetThreadIdentity() thread.Identity {
	return UnmarshalPrivateKey(cfg.Identity)
}
func (cfg *AppConfig) GetThreadDbPort() int {
	res, err := strconv.Atoi(strings.Split(cfg.ThreadDBAddr, ":")[1])
	if err != nil {
		log.Printf("Error extracting Thread DB port as int: %s\n", err.Error())
	}
	return res
}
func (cfg *AppConfig) NetworkMetadataThreadIdInitialized() bool {
	return cfg.NetworkMetadataThreadId != ""
}
func (cfg *AppConfig) Load() {
	f, err := os.Open(cfg.Path)
	if err != nil {
		log.Fatalf("Error opening config.yaml: %s", err.Error())
		return
	}
	defer f.Close()
	err = yaml.NewDecoder(f).Decode(&cfg)
	if err != nil {
		log.Fatalf("Error decoding config.yaml: %s", err.Error())
		return
	}
}
func (cfg *AppConfig) InitNetworkMetadataThreadId(threadId thread.ID) {
	tId, err := threadId.MarshalText()
	if err != nil {
		log.Printf("Error marshaling thread id: %s", err.Error())
	}
	cfg.NetworkMetadataThreadId = string(tId)
	if cfg.Path != "" {
		cfg.Save()
	}

}

func (cfg *AppConfig) GetNetworkMetadataThreadId() thread.ID {
	var dummy thread.ID
	dummy.UnmarshalText([]byte(string(cfg.NetworkMetadataThreadId)))
	return dummy
}
func (cfg *AppConfig) InitEccIdentity() {
	privateKey, _, err := crypto.GenerateEd25519Key(rand.Reader) // Private key is kept locally
	if err != nil {
		log.Fatalf("Errow while generating peer Ed25519 key. %v\n", err)
		return
	}
	bytes, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Errow retrieving Ed25519 peer key bytes. %v\n", err)
		return
	}
	cfg.Identity = b64.StdEncoding.EncodeToString(bytes)
	if cfg.Path != "" {
		cfg.Save()
	}
}

func (cfg *AppConfig) Save() {
	err := os.Truncate(cfg.Path, 0)
	if err != nil {
		log.Fatal("Error truncating config.yaml, terminating...")
		return
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening config.yaml %v\n", err)
	}
	log.Printf("\nLog Directory: %s\n", cfg.LogDirectory)
	dup := ConfigFile{
		HttpPort:                cfg.HttpPort,
		HttpsPort:               cfg.HttpsPort,
		ThreadDBAddr:            cfg.ThreadDBAddr,
		TLSCertPath:             cfg.TLSCertPath,
		TLSPrivKeyPath:          cfg.TLSPrivKeyPath,
		DevMode:                 cfg.DevMode,
		Identity:                cfg.Identity,
		BootstrapMultiaddr:      cfg.BootstrapperMultiaddr,
		BootstrappingCommsPort:  cfg.BootstrappingCommsPort,
		MasterNodeCommsPort:     cfg.MasterNodeCommsPort,
		NetworkMetadataThreadId: cfg.NetworkMetadataThreadId,
		LogDirectory:            cfg.LogDirectory,
		LocalIpAddr:             cfg.LocalIpAddr,
	}
	config, err := yaml.Marshal(&dup)

	if err != nil {
		log.Fatalf("Error while Marshaling Config. %v\n", err)
	}
	_, err = f.WriteString(string(config))
	if err != nil {
		log.Fatal(err.Error())
		f.Close()
	}
	err = f.Close()
	if err != nil {
		log.Fatal(err.Error())
	}
}

func UnmarshalPrivateKey(key string) thread.Identity {
	bytes, _ := b64.StdEncoding.DecodeString(key)
	identity, err := crypto.UnmarshalPrivateKey(bytes)
	if err != nil {
		log.Fatalf("error unmarshaling storage node private key: %s", err)
	}
	return thread.NewLibp2pIdentity(identity)
}
func getLocalIp1() string {
	ifaces, _ := net.Interfaces()
	// handle err
	var ip net.IP
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				if !ip.IsPrivate() {
					log.Printf("%s\n", ip.String())
				}

			}
			// process IP address
		}
	}

	return ip.String()
}

func (cfg *AppConfig) getLocalIp() string {
	if cfg.LocalIpAddr != "" {
		return cfg.LocalIpAddr
	}
	// Create the default consensus,
	// using the default configuration and no logger.
	consensus := externalip.DefaultConsensus(nil, nil)

	// By default Ipv4 or Ipv6 is returned,
	// use the function below to limit yourself to IPv4,
	// or pass in `6` instead to limit yourself to IPv6.
	// consensus.UseIPProtocol(4)

	// Get your IP,
	// which is never <nil> when err is <nil>.
	ip, err := consensus.ExternalIP()
	if err != nil {
		log.Fatalf("Error retrieving local IP address")
	}
	return ip.String()
}

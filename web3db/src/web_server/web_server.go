package webserv

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"web3db/src/common"
	"web3db/src/config"
	client "web3db/src/threaddb"
	"web3db/src/web3db"

	"github.com/gorilla/mux"
	"github.com/textileio/go-threads/core/thread"
	db "github.com/textileio/go-threads/db"
)

type webServInfo struct {
	httpPort  int
	httpsPort int
	tls_cert  string
	tls_pk    string
}
type WebServer struct {
	router *mux.Router
	info   webServInfo
	cfg    *config.AppConfig
}

const BlockchainSecret = "a;sldkfjas;dlfaweroi;gbnqaeruiogasdrfgsbdfklgjsdhnf;goajhnero;gihaeubervouaberoigaheroi8gfja;eorguiaer[0gi8a[0weg4haeorgaeo90ri8ghaneo9rghaebroignap;eo9i8r4hntga308ihnba[0gbhnaeori8hgnae0[p4gbhn[a'0w3o4ghjn[a"

var networkMetadata thread.ID
var selfId thread.Identity
var selfThreadDbAddr string

func New(cfg *config.AppConfig) WebServer {
	router := mux.NewRouter()
	info := webServInfo{cfg.HttpPort, cfg.HttpsPort, cfg.TLSCertPath, cfg.TLSPrivKeyPath}
	networkMetadata = cfg.GetNetworkMetadataThreadId()
	selfId = cfg.GetThreadIdentity()
	selfThreadDbAddr = cfg.ThreadDBAddr
	return WebServer{router, info, cfg}
}
func (serv *WebServer) Start() {
	serv.initEndpoints()
	if serv.info.httpsPort > 0 && serv.info.tls_cert != "" && serv.info.tls_pk != "" {
		log.Printf("HTTPS: Listening on port %d\n", serv.info.httpsPort)
		go log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", serv.info.httpsPort), serv.info.tls_cert, serv.info.tls_pk, serv.router))
	}
	if serv.info.httpPort > 0 {
		log.Printf("HTTP: Listening on port %d\n", serv.info.httpPort)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", serv.info.httpPort), serv.router))
	}
}

func (serv *WebServer) initEndpoints() {
	// CORS
	serv.router.HandleFunc("/api/new_db", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/delete_db", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/list_dbs", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_web3db_pubkey", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/list_collections", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_collection_info", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/find", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/new_collection", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/delete_collection", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/create_instance", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/delete_instance", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_thread_acl", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_instance_acl", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_collection_acl", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/update_thread_acl", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/update_instance_acl", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/update_collection_acl", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/update_instance", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_thread_info", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/get_thread_purchase_token", preFlightResourceHandler).Methods("OPTIONS")
	serv.router.HandleFunc("/api/list_dbs_for_sale", preFlightResourceHandler).Methods("OPTIONS")

	// threads
	serv.router.HandleFunc("/api/new_db", newDB).Methods("POST")
	serv.router.HandleFunc("/api/delete_db", deleteDB).Methods("POST")
	serv.router.HandleFunc("/api/list_dbs", listDBs).Methods("GET")
	serv.router.HandleFunc("/api/update_thread_acl", updateThreadAclEntry).Methods("POST")
	serv.router.HandleFunc("/api/get_thread_acl", getThreadAcl).Methods("GET")
	serv.router.HandleFunc("/api/get_thread_purchase_info", getThreadPurchaseInfo).Methods("GET")
	serv.router.HandleFunc("/api/get_thread_purchase_token", getThreadPurchaseToken).Methods("GET")
	serv.router.HandleFunc("/api/list_dbs_for_sale", listDBsForSale).Methods("GET")

	// collections
	serv.router.HandleFunc("/api/new_collection", createCollection).Methods("POST")
	serv.router.HandleFunc("/api/delete_collection", deleteCollection).Methods("POST")
	serv.router.HandleFunc("/api/list_collections", listCollections).Methods("GET")
	serv.router.HandleFunc("/api/get_collection_acl", getCollectionAcl).Methods("GET")
	serv.router.HandleFunc("/api/update_collection_acl", updateCollectionAclEntry).Methods("POST")
	serv.router.HandleFunc("/api/get_collection_info", getCollectionInfo).Methods("GET")

	// instances
	serv.router.HandleFunc("/api/create_instance", createInstance).Methods("POST")
	serv.router.HandleFunc("/api/delete_instance", deleteInstance).Methods("POST")
	serv.router.HandleFunc("/api/find", find).Methods("GET")
	serv.router.HandleFunc("/api/get_instance_acl", getInstanceAcl).Methods("GET")
	serv.router.HandleFunc("/api/update_instance_acl", updateInstanceAclEntry).Methods("POST")
	serv.router.HandleFunc("/api/update_instance", updateInstance).Methods("POST")

	// server public key exposure
	serv.router.HandleFunc("/api/get_web3db_pubkey", getStorageNodePubKey).Methods("GET")
}

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "status, content-type, identity")
}

// create new thread
func newDB(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.Header.Get("Origin")
	identity := r.Header.Get("identity")
	log.Printf("NewDB Request from: %s", requestor)
	var params common.NewDBParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		log.Printf("Decoding Error: %s\n", err.Error())
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error decoding URL parameter: threadId")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	threadId, err := a.NewDB(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Successfully created Thread %s\n", threadId)
	w.Header().Set("status", "200")
	json.NewEncoder(w).Encode(threadId)

}

// delete thread
func deleteDB(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.Header.Get("Origin")
	log.Printf("Recieved DeleteDB request from %s\n", requestor)
	var params common.DeleteDBParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid Request Body. Error decoding parameters", http.StatusBadRequest)
		return
	}
	identity := r.Header.Get("identity")
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)

	err = a.DeleteDB(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Successfully deleted Thread %s\n", params.ThreadID)
	w.Header().Set("status", "200")
}

// list threads
func listDBs(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.Header.Get("Origin")
	identity := r.Header.Get("identity")
	log.Printf("Recieved ListDBs request from %s\n", requestor)
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	jsonResponse, err := a.ListDBs()
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	w.Write(jsonResponse)
}

// list collections in a thread
func listCollections(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.Header.Get("Origin")
	log.Printf("Recieved ListCollections request from %s\n", requestor)
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		http.Error(w, "Missing required URL parameter: threadId", http.StatusBadRequest)
		log.Println("Missing URL parameter threadId")
		return
	}
	tId := keys[0]
	threadId, err := thread.Decode(tId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error decoding URL parameter: threadId")
		http.Error(w, "Error decoding URL parameter: threadId", http.StatusBadRequest)
		log.Printf("Error decoding URL parameter threadId: %s\n", err.Error())
		return
	}
	a := web3db.NewClient(r.Header.Get("identity"), selfThreadDbAddr, selfId, networkMetadata)
	jsonResponse, err := a.ListCollections(threadId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	w.Write(jsonResponse)
}

// create new collection in a thread
func createCollection(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved CreateCollections request from %s\n", requestor)
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	var params common.CreateCollectionParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Printf("Error decoding params: %s\n", err.Error())
		return
	}
	err = a.CreateCollection(params)
	if err != nil {
		w.Header().Set("status", "400")
		http.Error(w, err.Error(), http.StatusBadRequest)
		w.Header().Set("statusText", err.Error())
		return
	}
	w.Header().Set("status", "200")
}

// remove collection from a thread
func deleteCollection(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved DeleteCollections request from %s\n", requestor)
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	var params common.DeleteCollectionParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid Request Body.", http.StatusBadRequest)
		log.Printf("Error decoding params: %s\n", err.Error())
		return
	}
	err = a.DeleteCollection(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
}

// get collection schema information
func getCollectionInfo(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved GetCollectionInfo request from %s\n", requestor)
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		http.Error(w, "Missing required URL parameter: threadId", http.StatusBadRequest)
		return
	}
	tId := keys[0]
	threadId, err := thread.Decode(tId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error Decoding Thread ID parameter")
		http.Error(w, "Error decoding URL parameter: threadId", http.StatusBadRequest)
		log.Println("Error Decoding Thread ID parameter")
		return
	}
	keys, ok = r.URL.Query()["collectionName"]
	if !ok {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Missing required URL parameter: collectionName")
		http.Error(w, "Missing required URL parameter: collectionName", http.StatusBadRequest)
		log.Println("Error Decoding Thread ID parameter")
		return
	}
	collectionName := keys[0]
	info, err := a.GetCollectionInfo(collectionName, threadId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	jsonResponse, _ := json.Marshal(info)
	w.Write(jsonResponse)
}

// insert data into collection
func createInstance(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved CreateInstance request from %s\n", requestor)
	var params common.CreateInstanceParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid Request Body.", http.StatusBadRequest)
		log.Printf("Error: %s\n", err.Error())
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	ids, err := a.CreateInstance(params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusTeapot)
		w.Header().Set("statusText", "Missing required URL parameter: collectionName")
		return
	}
	json.NewEncoder(w).Encode(ids)
}

func deleteInstance(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved DeleteInstance request from %s\n", requestor)
	var params common.DeleteInstanceParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "Invalid Request Body.", http.StatusBadRequest)
		log.Printf("Error: %s\n", err.Error())
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	err = a.DeleteInstance(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
}

// query for instances in a collection
func find(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved find request from %s\n", requestor)
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		return
	}
	tId := keys[0]
	threadId, err := thread.Decode(tId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error Decoding Thread ID parameter")
		http.Error(w, "Error Decoding Thread ID parameter", http.StatusBadRequest)
		log.Println("Error Decoding Thread ID parameter")
		return
	}
	keys, ok = r.URL.Query()["collectionName"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing collectionName parameter")
		http.Error(w, "Missing collectionName parameter", http.StatusBadRequest)
		w.Header().Set("statusText", "Missing required URL parameter: collectionName")
		return
	}
	collectionName := keys[0]
	keys, ok = r.URL.Query()["query"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing query parameter")
		http.Error(w, "Missing required URL parameter: query", http.StatusBadRequest)
		w.Header().Set("statusText", "Missing required URL parameter: query")
		return
	}
	queryJson := keys[0]
	var query db.Query
	err = json.Unmarshal([]byte(queryJson), &query)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Invalid query Parameter")
		http.Error(w, "Invalid query Parameter", http.StatusBadRequest)
		log.Println("Error Decoding query parameter")
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	results, err := a.Find(threadId, collectionName, query)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// retrieve access control list for a thread
func getThreadAcl(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved getThreadAcl request from %s\n", requestor)
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		http.Error(w, "Missing threadId parameter", http.StatusBadRequest)
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		return
	}
	tId := keys[0]
	threadId, err := thread.Decode(tId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error Decoding Thread ID parameter")
		http.Error(w, "Error Decoding Thread ID parameter", http.StatusBadRequest)
		log.Println("Error Decoding Thread ID parameter")
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	res, err := a.GetThreadAcl(threadId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// retrieve acl for a collection
func getCollectionAcl(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved getCollectionAcl request from %s\n", requestor)
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		http.Error(w, "Missing threadId parameter", http.StatusBadRequest)
		return
	}
	tId := keys[0]
	threadId, err := thread.Decode(tId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error Decoding Thread ID parameter")
		http.Error(w, "Error Decoding Thread ID parameter", http.StatusBadRequest)
		log.Println("Error Decoding Thread ID parameter")
		return
	}
	keys, ok = r.URL.Query()["collectionName"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing collectionName parameter")
		w.Header().Set("statusText", "Missing required URL parameter: collectionName")
		http.Error(w, "Missing required URL parameter: collectionName", http.StatusBadRequest)
		return
	}
	collectionName := keys[0]
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	res, err := a.GetCollectionAcl(collectionName, threadId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// retrieve acl for an instance
func getInstanceAcl(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved getInstanceAcl request from %s\n", requestor)
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		return
	}
	tId := keys[0]
	threadId, err := thread.Decode(tId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error Decoding Thread ID parameter")
		http.Error(w, "Missing threadId parameter", http.StatusBadRequest)
		log.Println("Error Decoding Thread ID parameter")
		return
	}
	keys, ok = r.URL.Query()["collectionName"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		http.Error(w, "Error Decoding Thread ID parameter", http.StatusBadRequest)
		w.Header().Set("statusText", "Missing required URL parameter: collectionName")
		return
	}
	collectionName := keys[0]
	keys, ok = r.URL.Query()["instanceId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing instanceId parameter")
		http.Error(w, "Missing required URL parameter: instanceId", http.StatusBadRequest)
		w.Header().Set("statusText", "Missing required URL parameter: instanceId")
		return
	}
	instanceId := keys[0]
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	res, err := a.GetInstanceAcl(collectionName, threadId, instanceId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func updateThreadAclEntry(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved updateThreadAclEntry request from %s\n", requestor)
	var params common.UpdateThreadAclEntryParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	err = a.UpdateThreadAclEntry(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
}

func updateCollectionAclEntry(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved updateCollectionAclEntry request from %s\n", requestor)
	var params common.UpdateCollectionAclEntryParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	err = a.UpdateCollectionAclEntry(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
}

func updateInstanceAclEntry(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved updateInstanceAclEntry request from %s\n", requestor)
	var params common.UpdateInstanceAclEntryParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	err = a.UpdateInstanceAclEntry(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
}

func updateInstance(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	requestor := r.RemoteAddr
	identity := r.Header.Get("identity")
	log.Printf("Recieved updateInstance request from %s\n", requestor)
	var params common.UpdateInstanceParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	err = a.UpdateInstance(params)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
}

// retrieve this storage node's public key
func getStorageNodePubKey(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "status, content-type, identity")
	w.Header().Set("Content-Type", "application/octet-stream")
	requestor := r.RemoteAddr
	log.Printf("Recieved GetWeb3DBPubKey request from %s\n", requestor)
	a := web3db.NewClient("", selfThreadDbAddr, selfId, networkMetadata)
	json.NewEncoder(w).Encode(a.PublicKey())
}

func getThreadPurchaseInfo(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "status, content-type, identity")
	// ensure request comes from Smart Contract Oracle
	requestor := r.RemoteAddr
	blockChainSecret := r.Header.Get("blockChainSecret")
	if blockChainSecret != BlockchainSecret {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Permission Denied")
		return
	}

	log.Printf("Recieved getThreadPurchaseInfo request from %s\n", requestor)

	// extract GET params
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		return
	}
	tId := keys[0]

	client, err := client.New(selfThreadDbAddr, selfId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Permission Denied")
		return
	}
	res, err := client.Db.Find(context.Background(), networkMetadata, common.ThreadsForSaleSchemaName, db.Where("_id").Eq(tId), &common.ThreadsForSaleSchema{})
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Thread Not For Sale")
		return
	}
	if res == nil || len(res.([]*common.ThreadsForSaleSchema)) == 0 {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Thread Not For Sale")
		return
	}
	threadInfo := res.([]*common.ThreadsForSaleSchema)[0]
	jsonResponse, _ := json.Marshal(threadInfo)
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
	w.Write(jsonResponse)
}

func getThreadPurchaseToken(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "status, content-type, identity")
	w.Header().Set("Content-Type", "application/octet-stream")

	// ensure request comes from Smart Contract Oracle
	requestor := r.RemoteAddr
	blockChainSecret := r.Header.Get("blockChainSecret")
	if blockChainSecret != BlockchainSecret {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Permission Denied")
		return
	}
	// extract GET params
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		return
	}
	tId := keys[0]
	keys, ok = r.URL.Query()["purchaserPubKey"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: purchaserPubKey")
		return
	}
	purchaserPublicKey := keys[0]
	log.Printf("Recieved getThreadPurchaseToken request from %s\n", requestor)

	client, err := client.New(selfThreadDbAddr, selfId)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Permission Denied")
		return
	}

	// Retrieve thread purchase info
	res, _ := client.Db.Find(context.Background(), networkMetadata, common.ThreadPurchaseInfoSchemaName, db.Where("_id").Eq(tId), &common.ThreadPurchasesSchema{})
	entries := res.([]*common.ThreadPurchasesSchema)
	if len(entries) == 0 {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Thread Not For Sale")
		return
	}
	entry := entries[0]

	purchaserPubKey := thread.Libp2pPubKey{}
	err = purchaserPubKey.UnmarshalString(purchaserPublicKey)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Invalid Purchaser Public Key")
		return
	}

	// encrypt Thread Claim Token with the purchaser's public key
	encryptedClaimToken, err := common.ECCEnrypt(&purchaserPubKey, entry.ThreadClaimToken)
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", "Error Encrypting Claim Token")
		return
	}

	// send encrypted claim token
	json.NewEncoder(w).Encode(encryptedClaimToken)
}

func listDBsForSale(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "status, content-type, identity")
	w.Header().Set("Content-Type", "application/octet-stream")
	identity := r.Header.Get("identity")

	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	requestor := r.RemoteAddr
	res, _ := a.ListDBsForSale()
	log.Printf("Recieved GetThreadInfo request from %s\n", requestor)
	jsonResponse, _ := json.Marshal(res)
	w.Write(jsonResponse)
}

func claimThread(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "status, content-type, identity")
	w.Header().Set("Content-Type", "application/octet-stream")
	identity := r.Header.Get("identity")

	a := web3db.NewClient(identity, selfThreadDbAddr, selfId, networkMetadata)
	requestor := r.RemoteAddr
	log.Printf("ClaimThread request from %s", requestor)
	// extract GET params
	keys, ok := r.URL.Query()["threadId"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: threadId")
		return
	}
	tId := keys[0]
	keys, ok = r.URL.Query()["claimToken"]
	if !ok {
		w.Header().Set("status", "400")
		log.Println("Missing threadId parameter")
		w.Header().Set("statusText", "Missing required URL parameter: claimToken")
		return
	}
	claimToken := keys[0]
	err := a.ClaimThread(claimToken, thread.ID(tId))
	if err != nil {
		w.Header().Set("status", "400")
		w.Header().Set("statusText", err.Error())
		return
	}
	w.Header().Set("status", "200")
	w.Header().Set("content-type", "application/json")
}

func preFlightResourceHandler(w http.ResponseWriter, r *http.Request) {
	//Allow CORS here By * or specific origin
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "content-type, identity")
}

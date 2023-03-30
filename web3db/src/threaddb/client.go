package client

import (
	"context"
	"log"

	"github.com/textileio/go-threads/api/client"
	"github.com/textileio/go-threads/core/thread"
	"google.golang.org/grpc"
)

// Thread DB Client wrapper
type ThreadDBClient struct {
	Db       *client.Client // thread db client
	Tkn      thread.Token   // api token
	Identity string
}

// create a new ThreadDBClient. Initializes Thread DB server connection
func New(addr string, identity thread.Identity) (ThreadDBClient, error) {
	db, err := client.NewClient(addr, grpc.WithInsecure())
	if err != nil {
		log.Printf("Error connecting to thread db %s\n", err.Error())
	}
	threadToken, err := db.GetToken(context.Background(), identity)
	if err != nil {
		log.Printf("Error getting token: %s\n", err.Error())
	}
	client := ThreadDBClient{Db: db, Tkn: threadToken}
	return client, err
}

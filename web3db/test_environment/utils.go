package test_environment

import (
	"log"

	"github.com/textileio/go-threads/core/thread"
	"github.com/textileio/go-threads/db"
)

func printListDBs(res map[thread.ID]db.Info) {
	for id, info := range res {
		log.Printf("======= Thread Id: %s =======\n\n", id)
		log.Printf("======= DB Info =============\n")
		log.Printf("======= Name: %s ============\n\n", info.Name)
		log.Print("\n")

	}
}

package common

import (
	"strings"

	"github.com/textileio/go-threads/core/thread"
)

func ThreadIdFromMultiAddr(addr string) thread.ID {
	extracted := strings.Split(addr, "/")
	return thread.ID(extracted[len(extracted)-1])
}

func IpAddrFromMultiAddr(addr string) string {
	extracted := strings.Split(addr, "/")
	return extracted[2]
}

func PortFromMultiAddr(addr string) string {
	extracted := strings.Split(addr, "/")
	return extracted[4]
}

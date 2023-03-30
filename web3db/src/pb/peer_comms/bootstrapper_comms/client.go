package bootstrapper_comms

import (
	"context"
	"fmt"
	"web3db/src/common"
	pb "web3db/src/pb"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/textileio/go-threads/core/thread"
	"github.com/textileio/go-threads/db"
	"google.golang.org/grpc"
)

type BootstrappingCommsClient struct {
	c    pb.BootstrappingCommsClient
	conn *grpc.ClientConn
}

func NewBootstrappingCommsClient(addr string, opts ...grpc.DialOption) (*BootstrappingCommsClient, error) {
	conn, err := grpc.Dial(common.IpAddrFromMultiAddr(addr)+":"+common.PortFromMultiAddr(addr), grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("BootstrappingCommsClient: Failed to dial %s", addr))
	}
	return &BootstrappingCommsClient{
		c:    pb.NewBootstrappingCommsClient(conn),
		conn: conn,
	}, nil
}

func (peerComms *BootstrappingCommsClient) SendJoinRequest(peerId thread.Identity) (*db.Info, error) {
	req := pb.JoinNetworkRequest{
		PeerId: []byte(peerId.GetPublic().String()),
	}
	reply, err := peerComms.c.JoinNetwork(context.Background(), &req)
	if err != nil {
		return nil, err
	}
	key, err := thread.KeyFromBytes(reply.Info.Key)
	if err != nil {
		return nil, err
	}
	addrs := make([]ma.Multiaddr, len(reply.Info.Addrs))
	for i, bytes := range reply.Info.Addrs {
		addr, err := ma.NewMultiaddrBytes(bytes)
		if err != nil {
			return nil, err
		}
		addrs[i] = addr
	}
	peerComms.conn.Close()
	return &db.Info{
		Name:  reply.Info.Name,
		Key:   key,
		Addrs: addrs,
	}, nil
}

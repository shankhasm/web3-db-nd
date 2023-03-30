package bootstrapper_comms

import (
	"context"
	"fmt"
	"log"
	"net"
	pb "web3db/src/pb"
	client "web3db/src/threaddb"

	"github.com/textileio/go-threads/core/thread"
	"github.com/textileio/go-threads/db"
	"google.golang.org/grpc"
)

type BootstrappingCommsServer struct {
	pb.UnimplementedBootstrappingCommsServer
	port                    int
	threadDbAddr            string
	selfId                  thread.Identity
	networkMetadataThreadId thread.ID
	server                  *grpc.Server
}

func NewBootstrappingCommsServer(threadDbAddr string, selfId thread.Identity, port int, networkMetadataThreadId thread.ID) *BootstrappingCommsServer {
	return &BootstrappingCommsServer{
		port:                    port,
		threadDbAddr:            threadDbAddr,
		selfId:                  selfId,
		networkMetadataThreadId: networkMetadataThreadId,
	}
}
func (serv *BootstrappingCommsServer) JoinNetwork(ctx context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkReply, error) {
	dbInfo, err := serv.findInternalMetadataThreadInfo()
	if err != nil {
		return nil, err
	}
	log.Printf("Recieved JoinNetworkRequest from %s", req.PeerId)
	res := make([][]byte, len(dbInfo.Addrs))
	for i := range dbInfo.Addrs {
		res[i] = dbInfo.Addrs[i].Bytes()
	}
	info := pb.InternalMetadataThreadInfo{
		Addrs: res,
		Name:  dbInfo.Name,
		Key:   dbInfo.Key.Bytes(),
	}

	return &pb.JoinNetworkReply{Info: &info}, nil

}

func (serv *BootstrappingCommsServer) StartServer() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", serv.port))
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Failed to listen TCP on %s", fmt.Sprintf("localhost:%d", serv.port)))
	}
	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterBootstrappingCommsServer(grpcServer, serv)
	serv.server = grpcServer
	serv.server.Serve(lis)
	return nil
}

func (serv *BootstrappingCommsServer) StopServer() {
	serv.server.GracefulStop()
}

func (serv *BootstrappingCommsServer) findInternalMetadataThreadInfo() (*db.Info, error) {
	client, err := client.New(serv.threadDbAddr, serv.selfId)
	if err != nil {
		log.Printf("findInternalMetadataThreadInfo: failed to create ThreadDB client: %s", err)
		return nil, err
	}
	info, err := client.Db.GetDBInfo(context.Background(), serv.networkMetadataThreadId)
	if err != nil {
		log.Printf("findInternalMetadataThreadInfo: failed get db info for network metdata thread id %s: %s", serv.networkMetadataThreadId, err)
		return nil, err
	}
	return &info, nil

}

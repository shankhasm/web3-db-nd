package master_node_comms

import (
	"context"
	"fmt"
	"log"
	"net"
	"web3db/src/common"
	pb "web3db/src/pb"

	"github.com/textileio/go-threads/core/thread"
	"google.golang.org/grpc"
)

type MasterNodeCommsServer struct {
	pb.UnimplementedMasterNodeCommsServer
	port                    int
	threadDbAddr            string
	selfId                  thread.Identity
	networkMetadataThreadId thread.ID
	server                  *grpc.Server
	channel                 chan int
}

func NewMasterNodeCommsServer(threadDbAddr string, selfId thread.Identity, port int, networkMetadataThreadId thread.ID, channel chan int) *MasterNodeCommsServer {
	return &MasterNodeCommsServer{
		port:                    port,
		threadDbAddr:            threadDbAddr,
		selfId:                  selfId,
		networkMetadataThreadId: networkMetadataThreadId,
		channel:                 channel,
	}
}

func (serv *MasterNodeCommsServer) StartServer() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", serv.port))
	if err != nil {
		log.Printf("Failed to listen on %s", fmt.Sprintf("localhost:%d", serv.port))
		return
	}
	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterMasterNodeCommsServer(grpcServer, serv)
	serv.server = grpcServer
	log.Printf("Listening for MasterNodeAssignments on %s", fmt.Sprintf("localhost:%d", serv.port))
	err = serv.server.Serve(lis)
	if err != nil {
		log.Fatalf("Failed to listen on %s", fmt.Sprintf("localhost:%d", serv.port))
	}
}

func (serv *MasterNodeCommsServer) StopServer() {
	serv.server.GracefulStop()
}

func (serv *MasterNodeCommsServer) AssignMasterNode(ctx context.Context, req *pb.AssignMasterNodeRequest) (*pb.AssignMasterNodeReply, error) {
	log.Print("Recieved AssignMasterNodeRequest")
	serv.channel <- common.StartNodeQueueMaintenance
	return &pb.AssignMasterNodeReply{}, nil
}

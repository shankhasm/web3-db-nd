package master_node_comms

import (
	"context"
	"log"
	pb "web3db/src/pb"

	"google.golang.org/grpc"
)

type MasterNodeCommsClient struct {
	c    pb.MasterNodeCommsClient
	conn *grpc.ClientConn
}

func NewMasterNodeCommsClient(addr string, opts ...grpc.DialOption) *MasterNodeCommsClient {
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("%s", err)
		return nil
	}
	return &MasterNodeCommsClient{
		c:    pb.NewMasterNodeCommsClient(conn),
		conn: conn,
	}
}

func (client *MasterNodeCommsClient) AssignNewMasterNode() error {
	_, err := client.c.AssignMasterNode(context.Background(), &pb.AssignMasterNodeRequest{})
	client.conn.Close()
	return err
}

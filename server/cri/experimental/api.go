package experimental

import (
	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/experimental"

	"github.com/cri-o/cri-o/server"
)

type Service interface {
	pb.RuntimeServiceServer
}

type service struct {
	server *server.Server
}

// Register registers the runtime and image service with the provided grpc server
func Register(grpcServer *grpc.Server, crioServer *server.Server) {
	s := &service{crioServer}
	pb.RegisterRuntimeServiceServer(grpcServer, s)
}

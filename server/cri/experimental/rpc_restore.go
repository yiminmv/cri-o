package experimental

import (
	"context"

	"github.com/cri-o/cri-o/server/cri/types"
	pb "k8s.io/cri-api/pkg/apis/runtime/experimental"
)

func (s *service) RestoreContainer(ctx context.Context, req *pb.RestoreContainerRequest) (res *pb.RestoreContainerResponse, retErr error) {
	r := &types.RestoreContainerRequest{
		ID: req.Id,
		Options: &types.RestoreContainerOptions{
			Name:         req.Options.Name,
			PodSandboxID: req.Options.PodSandboxId,
			Labels:       req.Options.Labels,
			Annotations:  req.Options.Annotations,
			CommonOptions: &types.CheckpointRestoreOptions{
				Keep:           req.Options.CommonOptions.Keep,
				TCPEstablished: req.Options.CommonOptions.TcpEstablished,
				Archive:        req.Options.CommonOptions.Archive,
				Compression:    req.Options.CommonOptions.Compression,
			},
		},
	}

	response, err := s.server.RestoreContainer(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pb.RestoreContainerResponse{
		Id:                 response.ID,
		Pod:                response.Pod,
		RestoredContainers: response.RestoredContainers,
	}, nil
}

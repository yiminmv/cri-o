package server_test

import (
	"context"
	"io"
	"io/ioutil"
	"os"

	"github.com/containers/storage/pkg/archive"
	"github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/internal/storage"
	"github.com/cri-o/cri-o/server/cri/types"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var _ = t.Describe("ContainerRestore", func() {
	// Prepare the sut
	BeforeEach(func() {
		beforeEach()
		createDummyConfig()
		mockRuncInLibConfig()
		serverConfig.SetCheckpointRestore(true)
		setupSUT()
	})

	AfterEach(func() {
		afterEach()
		os.RemoveAll("config.dump")
		os.RemoveAll("cp.tar")
		os.RemoveAll("dump.log")
		os.RemoveAll("spec.dump")
	})

	t.Describe("ContainerRestore", func() {
		It("should fail because container does not exist", func() {
			// Given
			// When
			_, err := sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					ID: testContainer.ID(),
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to find container containerID: container with ID starting with containerID not found: ID does not exist`))
		})
	})
	t.Describe("ContainerRestore", func() {
		It("should fail because container is already running", func() {
			// Given
			addContainerAndSandbox()

			testContainer.SetState(&oci.ContainerState{
				State: specs.State{Status: oci.ContainerStateRunning},
			})
			testContainer.SetSpec(&specs.Spec{Version: "1.0.0"})

			// When
			_, err := sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					ID: testContainer.ID(),
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`cannot restore running container containerID`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive does not exist", func() {
			// Given
			// When
			_, err := sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: "does-not-exist",
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "cp.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to find container : Failed to open checkpoint archive cp.tar for import: open cp.tar: no such file or directory`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive is an empty file", func() {
			// Given
			archive, err := os.OpenFile("empty.tar", os.O_RDONLY|os.O_CREATE, 0o644)
			Expect(err).To(BeNil())
			archive.Close()
			defer func() { os.RemoveAll("empty.tar") }()
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: "does-not-exist",
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "empty.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(ContainSubstring(`failed to find container : Failed to open container definition`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive is not a tar file", func() {
			// Given
			err := ioutil.WriteFile("no.tar", []byte("notar"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("no.tar") }()
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: "does-not-exist",
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "no.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to find container : Unpacking of checkpoint archive no.tar failed: unexpected EOF`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive contains broken spec.dump", func() {
			// Given
			err := ioutil.WriteFile("spec.dump", []byte("not json"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("spec.dump") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"spec.dump"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: "does-not-exist",
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(ContainSubstring(`failed to find container : Failed to unmarshal container definition`))
			Expect(err.Error()).To(ContainSubstring(`spec.dump`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive contains empty config.dump and spec.dump", func() {
			// Given
			err := ioutil.WriteFile("spec.dump", []byte("{}"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("spec.dump") }()
			err = ioutil.WriteFile("config.dump", []byte("{}"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("config.dump") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"spec.dump", "config.dump"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: "does-not-exist",
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to find container : unexpected end of JSON input`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive contains broken config.dump", func() {
			// Given
			err := ioutil.WriteFile("spec.dump", []byte("{}"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("spec.dump") }()
			err = ioutil.WriteFile("config.dump", []byte("not json"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("config.dump") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"spec.dump", "config.dump"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: "does-not-exist",
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(ContainSubstring(`failed to find container : Failed to unmarshal container definition`))
			Expect(err.Error()).To(ContainSubstring(`config.dump`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive contains empty config.dump", func() {
			// Given
			addContainerAndSandbox()

			err := ioutil.WriteFile("spec.dump", []byte(`{"annotations":{"io.kubernetes.cri-o.Metadata":"{\"name\":\"container-to-restore\"}"}}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("spec.dump") }()
			err = ioutil.WriteFile("config.dump", []byte("{}"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("config.dump") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"spec.dump", "config.dump"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: testSandbox.ID(),
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to find container : CreateContainerRequest.ContainerConfig.Image.Image is empty`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because archive contains no actual checkpoint", func() {
			// Given
			addContainerAndSandbox()
			testContainer.SetStateAndSpoofPid(&oci.ContainerState{
				State: specs.State{Status: oci.ContainerStateRunning},
			})

			gomock.InOrder(
				imageServerMock.EXPECT().ResolveNames(gomock.Any(), gomock.Any()).Return([]string{"image"}, nil),
				imageServerMock.EXPECT().ImageStatus(gomock.Any(), gomock.Any()).Return(&storage.ImageResult{ID: "image"}, nil),
				runtimeServerMock.EXPECT().CreateContainer(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(storage.ContainerInfo{
						RunDir: "/tmp",
						Config: &v1.Image{Config: v1.ImageConfig{
							Entrypoint: []string{"entrypoint.sh"},
						}},
					}, nil),
				runtimeServerMock.EXPECT().StartContainer(gomock.Any()).Return("newID", nil),
				imageServerMock.EXPECT().GetStore().Return(storeMock),
				storeMock.EXPECT().Mount(gomock.Any(), gomock.Any()).Return("/tmp/", nil),
			)

			err := ioutil.WriteFile("spec.dump", []byte(`{"annotations":{"io.kubernetes.cri-o.Metadata":"{\"name\":\"container-to-restore\"}"}}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("spec.dump") }()
			err = ioutil.WriteFile("config.dump", []byte(`{"rootfsImageName": "image"}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("config.dump") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"spec.dump", "config.dump"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: testSandbox.ID(),
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(ContainSubstring(`A complete checkpoint for this container cannot be found`))
		})
	})
	t.Describe("ContainerRestore from archive into existing pod", func() {
		It("should fail because checkpoint archive does not exist", func() {
			// Given
			addContainerAndSandbox()
			// When
			_, err := sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						PodSandboxID: testSandbox.ID(),
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "cp.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to find container : Failed to open checkpoint archive cp.tar for import: open cp.tar: no such file or directory`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because checkpoint archive is empty", func() {
			// Given
			archive, err := os.OpenFile("empty.tar", os.O_RDONLY|os.O_CREATE, 0o644)
			Expect(err).To(BeNil())
			archive.Close()
			defer func() { os.RemoveAll("empty.tar") }()
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "empty.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(ContainSubstring(`failed to restore pod : Failed to open container definition`))
			Expect(err.Error()).To(ContainSubstring(`pod.options`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because checkpoint archive does not exist", func() {
			// Given
			// When
			_, err := sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "cp.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to restore pod : Failed to open pod archive cp.tar for import: open cp.tar: no such file or directory`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because checkpoint archive is not a tar archive", func() {
			// Given
			err := ioutil.WriteFile("no.tar", []byte("notar"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("no.tar") }()
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "no.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to restore pod : Unpacking of checkpoint archive no.tar failed: unexpected EOF`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because pod.options is empty", func() {
			// Given
			err := ioutil.WriteFile("pod.options", []byte("{}"), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("pod.options") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"pod.options"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to restore pod : cannot import Pod Checkpoint archive version 0`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because pod.dump does not exist", func() {
			// Given
			err := ioutil.WriteFile("pod.options", []byte(`{"Version":1}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("pod.options") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"pod.options"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(ContainSubstring(`failed to restore pod : Failed to open container definition`))
			Expect(err.Error()).To(ContainSubstring(`pod.dump`))
		})
	})
	t.Describe("ContainerRestore from archive into new pod", func() {
		It("should fail because pod.dump metadata is empty", func() {
			// Given
			err := ioutil.WriteFile("pod.options", []byte(`{"Version":1}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("pod.options") }()
			err = ioutil.WriteFile("pod.dump", []byte(`{"metadata":{}}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("pod.dump") }()
			outFile, err := os.Create("archive.tar")
			Expect(err).To(BeNil())
			defer outFile.Close()
			input, err := archive.TarWithOptions(".", &archive.TarOptions{
				Compression:      archive.Uncompressed,
				IncludeSourceDir: true,
				IncludeFiles:     []string{"pod.options", "pod.dump"},
			})
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("archive.tar") }()
			_, err = io.Copy(outFile, input)
			Expect(err).To(BeNil())
			// When
			_, err = sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{
							Archive: "archive.tar",
						},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`failed to restore pod : setting sandbox config: PodSandboxConfig.Metadata.Name should not be empty`))
		})
	})
})

var _ = t.Describe("ContainerRestore with CheckpointRestore set to false", func() {
	// Prepare the sut
	BeforeEach(func() {
		beforeEach()
		setupSUT()
	})

	AfterEach(afterEach)

	t.Describe("ContainerRestore", func() {
		It("should fail with checkpoint/restore support not available", func() {
			// Given
			// When
			_, err := sut.RestoreContainer(context.Background(),
				&types.RestoreContainerRequest{
					ID: testContainer.ID(),
					Options: &types.RestoreContainerOptions{
						CommonOptions: &types.CheckpointRestoreOptions{},
					},
				})

			// Then
			Expect(err.Error()).To(Equal(`checkpoint/restore support not available`))
		})
	})
})

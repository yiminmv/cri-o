package oci_test

import (
	"io/ioutil"
	"os"

	"github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/pkg/annotations"
	libconfig "github.com/cri-o/cri-o/pkg/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The actual test suite
var _ = t.Describe("Oci", func() {
	t.Describe("New", func() {
		It("should succeed with default config", func() {
			// Given
			c, err := libconfig.DefaultConfig()
			Expect(err).To(BeNil())

			// When
			runtime := oci.New(c)

			// Then
			Expect(runtime).NotTo(BeNil())
		})
	})

	t.Describe("Oci", func() {
		// The system under test
		var sut *oci.Runtime

		// Test constants
		const (
			invalidRuntime     = "invalid"
			defaultRuntime     = "runc"
			usernsRuntime      = "userns"
			performanceRuntime = "high-performance"
		)
		runtimes := libconfig.Runtimes{
			defaultRuntime: {
				RuntimePath: "/bin/sh",
				RuntimeType: "",
				RuntimeRoot: "/run/runc",
			}, invalidRuntime: {},
			usernsRuntime: {
				RuntimePath:        "/bin/sh",
				RuntimeType:        "",
				RuntimeRoot:        "/run/runc",
				AllowedAnnotations: []string{annotations.UsernsModeAnnotation},
			},
			performanceRuntime: {
				RuntimePath: "/bin/sh",
				RuntimeType: "",
				RuntimeRoot: "/run/runc",
				AllowedAnnotations: []string{
					annotations.CPULoadBalancingAnnotation,
					annotations.IRQLoadBalancingAnnotation,
					annotations.CPUQuotaAnnotation,
					annotations.OCISeccompBPFHookAnnotation,
				},
			},
		}

		BeforeEach(func() {
			var err error
			config, err = libconfig.DefaultConfig()
			Expect(err).To(BeNil())
			config.DefaultRuntime = defaultRuntime
			config.Runtimes = runtimes

			sut = oci.New(config)
			Expect(sut).NotTo(BeNil())
		})

		It("should succeed to retrieve the runtimes", func() {
			// Given
			// When
			result := sut.Runtimes()

			// Then
			Expect(result).To(Equal(runtimes))
		})

		It("should succeed to validate a runtime handler", func() {
			// Given
			// When
			handler, err := sut.ValidateRuntimeHandler(defaultRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(handler).To(Equal(runtimes[defaultRuntime]))
		})
		It("AllowUsernsAnnotation should be true when set", func() {
			// Given
			// When
			allowed, err := sut.AllowUsernsAnnotation(usernsRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(allowed).To(Equal(true))
		})
		It("AllowUsernsAnnotation should be false when not set", func() {
			// Given
			// When
			allowed, err := sut.AllowUsernsAnnotation(defaultRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(allowed).To(Equal(false))
		})
		It("AllowUsernsAnnotation should be false when runtime invalid", func() {
			// Given
			// When
			allowed, err := sut.AllowUsernsAnnotation(invalidRuntime)

			// Then
			Expect(err).NotTo(BeNil())
			Expect(allowed).To(Equal(false))
		})
		It("AllowCPULoadBalancingAnnotation should be true when set", func() {
			// Given
			// When
			allowed, err := sut.AllowCPULoadBalancingAnnotation(performanceRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(allowed).To(Equal(true))
		})
		It("AllowCPUQuotaAnnotation should be true when set", func() {
			// Given
			// When
			allowed, err := sut.AllowCPUQuotaAnnotation(performanceRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(allowed).To(Equal(true))
		})
		It("AllowIRQLoadBalancingAnnotation should be true when set", func() {
			// Given
			// When
			allowed, err := sut.AllowIRQLoadBalancingAnnotation(performanceRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(allowed).To(Equal(true))
		})
		It("AllowOCISeccompBPFHookAnnotation should be true when set", func() {
			// Given
			// When
			allowed, err := sut.AllowOCISeccompBPFHookAnnotation(performanceRuntime)

			// Then
			Expect(err).To(BeNil())
			Expect(allowed).To(Equal(true))
		})
		It("AllowOCISeccompBPFHookAnnotation should be false when runtime invalid", func() {
			// Given
			// When
			allowed, err := sut.AllowOCISeccompBPFHookAnnotation(invalidRuntime)

			// Then
			Expect(err).NotTo(BeNil())
			Expect(allowed).To(Equal(false))
		})
		It("CheckpointContainer should succeed", func() {
			// Given
			beforeEach(sandboxID)
			defer func() { os.RemoveAll("dump.log") }()
			config.Runtimes["runc"] = &libconfig.RuntimeHandler{
				RuntimePath: "/bin/true",
			}

			specgen := &specs.Spec{
				Version: "1.0.0",
				Process: &specs.Process{
					SelinuxLabel: "",
				},
				Linux: &specs.Linux{
					MountLabel: "",
				},
			}
			// When
			err := sut.CheckpointContainer(myContainer, specgen, false)

			// Then
			Expect(err).To(BeNil())
		})
		It("CheckpointContainer should fail", func() {
			// Given
			defer func() { os.RemoveAll("dump.log") }()
			beforeEach(sandboxID)
			config.Runtimes["runc"] = &libconfig.RuntimeHandler{
				RuntimePath: "/bin/false",
			}

			specgen := &specs.Spec{
				Version: "1.0.0",
				Process: &specs.Process{
					SelinuxLabel: "",
				},
				Linux: &specs.Linux{
					MountLabel: "",
				},
			}
			// When
			err := sut.CheckpointContainer(myContainer, specgen, true)

			// Then
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring(`/bin/false`))
			Expect(err.Error()).To(ContainSubstring("containerID` failed"))
		})
		It("RestoreContainer should fail with desintation sandbox detection", func() {
			// Given
			beforeEach(sandboxID)
			specgen := &specs.Spec{
				Version: "1.0.0",
			}
			err := os.Mkdir("checkpoint", 0o700)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("checkpoint") }()
			inventory, err := os.OpenFile("checkpoint/inventory.img", os.O_RDONLY|os.O_CREATE, 0o644)
			Expect(err).To(BeNil())
			inventory.Close()

			// When
			err = sut.RestoreContainer(myContainer, specgen, 42, "no-parent-cgroup-exists")

			// Then
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("failed to detect destination sandbox of to be restored container containerID"))
		})
		It("RestoreContainer should fail with desintation sandbox detection", func() {
			// Given
			beforeEach("")
			specgen := &specs.Spec{
				Version: "1.0.0",
			}
			err := os.Mkdir("checkpoint", 0o700)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("checkpoint") }()
			inventory, err := os.OpenFile("checkpoint/inventory.img", os.O_RDONLY|os.O_CREATE, 0o644)
			Expect(err).To(BeNil())
			inventory.Close()

			// When
			err = sut.RestoreContainer(myContainer, specgen, 42, "no-parent-cgroup-exists")

			// Then
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("failed to detect sandbox of to be restored container containerID"))
		})
		It("RestoreContainer should fail", func() {
			// Given
			beforeEach(sandboxID)
			specgen := &specs.Spec{
				Version:     "1.0.0",
				Annotations: map[string]string{"io.kubernetes.cri-o.SandboxID": "sandboxID"},
				Linux: &specs.Linux{
					MountLabel: ".",
				},
			}
			err := os.Mkdir("checkpoint", 0o700)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("checkpoint") }()
			inventory, err := os.OpenFile("checkpoint/inventory.img", os.O_RDONLY|os.O_CREATE, 0o644)
			Expect(err).To(BeNil())
			inventory.Close()

			err = ioutil.WriteFile("config.json", []byte(`{"ociVersion": "1.0.0","annotations": {"io.kubernetes.cri-o.SandboxID": "sandboxID"},"linux": {"mountLabel": ""}}`), 0o644)
			Expect(err).To(BeNil())
			defer func() { os.RemoveAll("config.json") }()

			config.Conmon = "/bin/true"

			// When
			err = sut.RestoreContainer(myContainer, specgen, 42, "no-parent-cgroup-exists")
			defer func() { os.RemoveAll("restore.log") }()

			// Then
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("failed to add conmon to systemd sandbox cgroup"))
		})
		It("RestoreContainer should fail with missing inventory", func() {
			// Given
			beforeEach(sandboxID)
			specgen := &specs.Spec{
				Version:     "1.0.0",
				Annotations: map[string]string{"io.kubernetes.cri-o.SandboxID": "sandboxID"},
				Linux: &specs.Linux{
					MountLabel: ".",
				},
			}
			// When
			err := sut.RestoreContainer(myContainer, specgen, 42, "no-parent-cgroup-exists")

			// Then
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("A complete checkpoint for this container cannot be found, cannot restore: stat checkpoint/inventory.img: no such file or directory"))
		})
	})

	t.Describe("ExecSyncError", func() {
		It("should succeed to get the exec sync error", func() {
			// Given
			sut := oci.ExecSyncError{}

			// When
			result := sut.Error()

			// Then
			Expect(result).To(ContainSubstring("error"))
		})
	})
})

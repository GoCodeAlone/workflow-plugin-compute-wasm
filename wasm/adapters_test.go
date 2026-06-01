package wasm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	computecontainer "github.com/GoCodeAlone/workflow-plugin-compute-container/container"
	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestWASMRunRequestFromComponentWorkload(t *testing.T) {
	component := []byte("fake-wasm")
	req, err := NewWASMRunRequest(WASMInvocationOptions{
		TaskID:  "task-1",
		LeaseID: "lease-1",
		Kind:    core.WorkloadWASMComponent,
		WASM: &core.WASMWorkload{
			ComponentRef:    "artifact://edge/echo.wasm",
			ComponentDigest: SHA256Ref(component),
			ABI:             DefaultWASMABI,
			Operation:       "handle_request",
			Input:           json.RawMessage(`{"path":"/"}`),
		},
		Limits: core.ResourceLimits{MemoryBytes: 32 << 20},
	})
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if req.ProtocolVersion != core.Version || req.TaskID != "task-1" || req.LeaseID != "lease-1" {
		t.Fatalf("identity not propagated: %+v", req)
	}
	if req.ComponentDigest != SHA256Ref(component) || req.Operation != "handle_request" {
		t.Fatalf("workload not propagated: %+v", req)
	}
}

func TestWASMRunRequestFromProviderWorkloadDefaultsABI(t *testing.T) {
	component := []byte("fake-provider-wasm")
	req, err := NewWASMRunRequest(WASMInvocationOptions{
		TaskID:  "task-2",
		LeaseID: "lease-2",
		Kind:    core.WorkloadProvider,
		Provider: &core.ProviderWorkload{
			ProviderConfig: core.ProviderConfig{
				PluginID:   "workflow-plugin-product-capture",
				ProviderID: "browser",
				ContractID: "product-capture.browser.v1",
				Version:    "v0.1.0",
				ConfigRef:  "config://browser",
			},
			ComponentRef:    "provider://workflow-plugin-product-capture/browser.wasm",
			ComponentDigest: SHA256Ref(component),
			Operation:       "capture",
			Input:           json.RawMessage(`{"url":"https://example.invalid"}`),
		},
	})
	if err != nil {
		t.Fatalf("new provider request: %v", err)
	}
	if req.ABI != DefaultWASMABI {
		t.Fatalf("abi = %q want %q", req.ABI, DefaultWASMABI)
	}
	if req.ProviderConfig.PluginID != "workflow-plugin-product-capture" {
		t.Fatalf("provider config not propagated: %+v", req.ProviderConfig)
	}
}

func TestWazeroRuntimeRunsExportedI32Function(t *testing.T) {
	component := minimalReturn42WASM()
	workspace := t.TempDir()
	result, err := (WazeroRuntime{}).RunWASM(context.Background(), WASMRunRequest{
		ProtocolVersion: core.Version,
		TaskID:          "task-wasm",
		LeaseID:         "lease-wasm",
		ComponentRef:    "artifact://edge/return42.wasm",
		ComponentDigest: SHA256Ref(component),
		ABI:             DefaultWASMABI,
		Operation:       "run",
		Input:           json.RawMessage(`{"ignored":true}`),
		Component:       component,
		Workspace:       workspace,
		Limits:          core.ResourceLimits{RuntimeSeconds: 2, OutputBytes: 1024},
	})
	if err != nil {
		t.Fatalf("run wazero: %v stderr=%s", err, result.Stderr)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d want 0", result.ExitCode)
	}
	if !strings.Contains(string(result.Stdout), `"result":42`) || !strings.Contains(string(result.Stdout), `"artifacts":["result_json"]`) {
		t.Fatalf("stdout = %s", result.Stdout)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "result_json"))
	if err != nil {
		t.Fatalf("result artifact missing: %v", err)
	}
	if !strings.Contains(string(data), `"result":42`) {
		t.Fatalf("artifact = %s", data)
	}
}

func TestWASMMemoryLimitPagesUsesTaskLimitAndConservativeDefault(t *testing.T) {
	if got := WASMMemoryLimitPages(0); got != 2048 {
		t.Fatalf("default pages = %d want 2048", got)
	}
	if got := WASMMemoryLimitPages(1); got != 1 {
		t.Fatalf("minimum pages = %d want 1", got)
	}
	if got := WASMMemoryLimitPages(128<<20 + 1); got != 2049 {
		t.Fatalf("ceil pages = %d want 2049", got)
	}
}

func TestProductCaptureBrowserInvocationAndAdapter(t *testing.T) {
	runtime := &recordingSandboxRuntime{}
	adapter := SandboxRuntimeProductCaptureBrowserAdapter{Runtime: runtime}
	workspace := t.TempDir()
	invocation, err := NewProductCaptureBrowserInvocation(ProductCaptureBrowserInvocationOptions{
		TaskID:    "task-product",
		LeaseID:   "lease-product",
		Image:     "ghcr.io/gocodealone/product-capture-runtime:latest",
		Workspace: workspace,
		Network:   computecontainer.SandboxNetworkBridge,
		Timeout:   2 * time.Second,
		Workload: core.ProductCaptureWorkload{
			URL:            "https://www.amazon.com/dp/B08H75RTZ8",
			AllowedHosts:   []string{"www.amazon.com", "amazon.com"},
			CaptureMode:    core.ProductCaptureModeBrowser,
			TimeoutSeconds: 30,
			MaxHTMLBytes:   1 << 20,
			MaxImageCount:  8,
		},
		Limits: core.ResourceLimits{OutputBytes: 4096},
	})
	if err != nil {
		t.Fatalf("new invocation: %v", err)
	}
	result, err := adapter.RunProductCaptureBrowser(context.Background(), invocation)
	if err != nil {
		t.Fatalf("run adapter: %v", err)
	}
	if !runtime.availableCalled || !runtime.called {
		t.Fatalf("runtime calls available=%v run=%v", runtime.availableCalled, runtime.called)
	}
	if runtime.request.WorkingDir != "/workspace" || runtime.request.Network != computecontainer.SandboxNetworkBridge {
		t.Fatalf("sandbox request = %+v", runtime.request)
	}
	if !slicesContains(runtime.request.Command, "--request") || !slicesContains(runtime.request.Command, "--output") {
		t.Fatalf("command = %+v", runtime.request.Command)
	}
	if result.Stdout == nil || result.ExitCode != 0 {
		t.Fatalf("result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(workspace, ProductCaptureRequestPath)); err != nil {
		t.Fatalf("request file missing: %v", err)
	}
}

func TestRuntimeAdapterContractsValidate(t *testing.T) {
	wasmContract := WASMComponentContract(core.RuntimeDescriptor{
		Name:                  WASMComponentProviderName,
		Version:               "dev",
		ExecutionSecurityTier: core.ExecutionWASMCapability,
		ProofTier:             core.ProofArtifactHash,
	})
	if err := wasmContract.Validate(); err != nil {
		t.Fatalf("wasm contract invalid: %v", err)
	}
	if len(wasmContract.WorkloadKinds) != 2 || wasmContract.WorkloadKinds[0] != core.WorkloadWASMComponent {
		t.Fatalf("wasm workload kinds = %+v", wasmContract.WorkloadKinds)
	}

	browserContract := ProductCaptureBrowserContract(core.RuntimeDescriptor{
		Name:                  ProductCaptureBrowserProviderName,
		Version:               "dev",
		ExecutionSecurityTier: core.ExecutionSandboxedContainer,
		ProofTier:             core.ProofArtifactHash,
		ImageDigest:           SHA256Ref([]byte("image")),
		RootFSDigest:          SHA256Ref([]byte("rootfs")),
	})
	if err := browserContract.Validate(); err != nil {
		t.Fatalf("browser contract invalid: %v", err)
	}
	if browserContract.WorkloadKinds[0] != core.WorkloadProductCapture {
		t.Fatalf("browser workload kinds = %+v", browserContract.WorkloadKinds)
	}
}

type recordingSandboxRuntime struct {
	availableCalled bool
	called          bool
	request         computecontainer.SandboxRunRequest
}

func (r *recordingSandboxRuntime) Available(context.Context) error {
	r.availableCalled = true
	return nil
}

func (r *recordingSandboxRuntime) Run(_ context.Context, req computecontainer.SandboxRunRequest) (computecontainer.SandboxRunResult, error) {
	r.called = true
	r.request = req
	return computecontainer.SandboxRunResult{ExitCode: 0, Stdout: []byte("captured")}, nil
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func minimalReturn42WASM() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00,
		0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
	}
}

package wasm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	computecontainer "github.com/GoCodeAlone/workflow-plugin-compute-container/container"
	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"github.com/tetratelabs/wazero"
)

const (
	WASMComponentProviderName                    = "wasm-component"
	WASMComponentOperationRun                    = "run-wasm-component"
	ProductCaptureBrowserProviderName            = "product-capture-browser"
	ProductCaptureBrowserOperationCapture        = "capture-product-browser"
	ProductCaptureProviderBinaryPath             = "provider/product-capture-provider"
	ProductCaptureRequestPath                    = "request.json"
	ProductCaptureSnapshotPath                   = "snapshot.json"
	DefaultWASMABI                               = "wasm-export-i32-v1"
	defaultWASMRuntimeName                       = "wfcompute-wasm-component"
	defaultWASMComponentMemoryBytes       int64  = 128 << 20
	maxWASMMemoryPages                    uint32 = 65536
)

type WASMRunRequest struct {
	ProtocolVersion string              `json:"protocol_version"`
	TaskID          string              `json:"task_id"`
	LeaseID         string              `json:"lease_id"`
	ProviderConfig  core.ProviderConfig `json:"provider_config,omitzero"`
	ComponentRef    string              `json:"component_ref"`
	ComponentDigest string              `json:"component_digest"`
	ABI             string              `json:"abi"`
	Operation       string              `json:"operation"`
	Input           json.RawMessage     `json:"input"`
	Component       []byte              `json:"-"`
	Workspace       string              `json:"-"`
	Limits          core.ResourceLimits `json:"-"`
}

func (r WASMRunRequest) Validate() error {
	var errs []error
	if r.ProtocolVersion != core.Version {
		errs = append(errs, fmt.Errorf("protocol_version = %q, want %q", r.ProtocolVersion, core.Version))
	}
	if strings.TrimSpace(r.TaskID) == "" {
		errs = append(errs, errors.New("task_id is required"))
	}
	if strings.TrimSpace(r.LeaseID) == "" {
		errs = append(errs, errors.New("lease_id is required"))
	}
	if err := validateComponentRef(r.ComponentRef); err != nil {
		errs = append(errs, fmt.Errorf("component_ref: %w", err))
	}
	if !validSHA256Digest(r.ComponentDigest) {
		errs = append(errs, errors.New("component_digest must be sha256:<64 hex chars>"))
	}
	if strings.TrimSpace(r.ABI) == "" {
		errs = append(errs, errors.New("abi is required"))
	}
	if strings.TrimSpace(r.Operation) == "" {
		errs = append(errs, errors.New("operation is required"))
	}
	return errors.Join(errs...)
}

type WASMRunResult = core.RuntimeExecutionResult

type WASMRuntime interface {
	RunWASM(context.Context, WASMRunRequest) (WASMRunResult, error)
}

type WASMInvocationOptions struct {
	TaskID   string
	LeaseID  string
	Kind     core.WorkloadKind
	WASM     *core.WASMWorkload
	Provider *core.ProviderWorkload
	Limits   core.ResourceLimits
}

func NewWASMRunRequest(opts WASMInvocationOptions) (WASMRunRequest, error) {
	switch opts.Kind {
	case core.WorkloadWASMComponent:
		if opts.WASM == nil {
			return WASMRunRequest{}, errors.New("wasm workload is required")
		}
		if err := opts.WASM.Validate(); err != nil {
			return WASMRunRequest{}, err
		}
		workload := opts.WASM
		req := WASMRunRequest{
			ProtocolVersion: core.Version,
			TaskID:          opts.TaskID,
			LeaseID:         opts.LeaseID,
			ComponentRef:    workload.ComponentRef,
			ComponentDigest: workload.ComponentDigest,
			ABI:             workload.ABI,
			Operation:       workload.Operation,
			Input:           slices.Clone(workload.Input),
			Limits:          opts.Limits,
		}
		if err := req.Validate(); err != nil {
			return WASMRunRequest{}, err
		}
		return req, nil
	case core.WorkloadProvider:
		if opts.Provider == nil {
			return WASMRunRequest{}, errors.New("provider workload is required")
		}
		if err := opts.Provider.Validate(); err != nil {
			return WASMRunRequest{}, err
		}
		workload := opts.Provider
		req := WASMRunRequest{
			ProtocolVersion: core.Version,
			TaskID:          opts.TaskID,
			LeaseID:         opts.LeaseID,
			ProviderConfig:  workload.ProviderConfig,
			ComponentRef:    workload.ComponentRef,
			ComponentDigest: workload.ComponentDigest,
			ABI:             firstNonEmpty(workload.ABI, DefaultWASMABI),
			Operation:       workload.Operation,
			Input:           slices.Clone(workload.Input),
			Limits:          opts.Limits,
		}
		if err := req.Validate(); err != nil {
			return WASMRunRequest{}, err
		}
		return req, nil
	default:
		return WASMRunRequest{}, fmt.Errorf("workload kind %q is not supported by %s", opts.Kind, WASMComponentProviderName)
	}
}

type WazeroRuntime struct{}

func (WazeroRuntime) RunWASM(ctx context.Context, req WASMRunRequest) (WASMRunResult, error) {
	if err := req.Validate(); err != nil {
		return WASMRunResult{}, err
	}
	if len(req.Component) == 0 {
		return WASMRunResult{}, errors.New("wasm component bytes are required")
	}
	if req.ABI != DefaultWASMABI {
		return WASMRunResult{}, fmt.Errorf("unsupported wasm abi %q", req.ABI)
	}
	if req.Workspace == "" {
		return WASMRunResult{}, errors.New("workspace is required")
	}
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(WASMMemoryLimitPages(req.Limits.MemoryBytes)).
		WithCloseOnContextDone(true).
		WithDebugInfoEnabled(false))
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, req.Component)
	if err != nil {
		return WASMRunResult{}, fmt.Errorf("compile wasm component: %w", err)
	}
	var stdout, stderr bytes.Buffer
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().
		WithName(defaultWASMRuntimeName).
		WithStdin(BoundedWASMStdin(req.Input)).
		WithStdout(&stdout).
		WithStderr(&stderr))
	if err != nil {
		return WASMRunResult{Stderr: stderr.Bytes()}, fmt.Errorf("instantiate wasm component: %w", err)
	}
	defer module.Close(ctx)
	fn := module.ExportedFunction(req.Operation)
	if fn == nil {
		return WASMRunResult{Stderr: stderr.Bytes()}, fmt.Errorf("wasm export %q not found", req.Operation)
	}
	results, err := fn.Call(ctx)
	if err != nil {
		return WASMRunResult{Stderr: stderr.Bytes()}, fmt.Errorf("call wasm export %q: %w", req.Operation, err)
	}
	value := 0
	if len(results) > 0 {
		value = int(results[0])
	}
	if stdout.Len() == 0 {
		artifact := fmt.Appendf(nil, `{"result":%d}`+"\n", value)
		path, err := resolveInside(req.Workspace, "result_json")
		if err != nil {
			return WASMRunResult{Stderr: stderr.Bytes()}, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return WASMRunResult{Stderr: stderr.Bytes()}, err
		}
		if err := os.WriteFile(path, artifact, 0o600); err != nil {
			return WASMRunResult{Stderr: stderr.Bytes()}, err
		}
		_, _ = fmt.Fprintf(&stdout, `{"result":%d,"artifacts":["result_json"]}`+"\n", value)
	}
	return WASMRunResult{
		ExitCode: 0,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ResourceUsage: core.ResourceUsage{
			OutputBytes: int64(stdout.Len() + stderr.Len()),
		},
	}, nil
}

type ProductCaptureBrowserRuntimeInvocation struct {
	Request   core.RuntimeExecutionRequest
	Image     string
	Workspace string
	Network   string
	Timeout   time.Duration
}

type ProductCaptureBrowserInvocationOptions struct {
	TaskID    string
	LeaseID   string
	Image     string
	Workspace string
	Network   string
	Timeout   time.Duration
	Workload  core.ProductCaptureWorkload
	Limits    core.ResourceLimits
}

type ProductCaptureBrowserRuntime interface {
	RunProductCaptureBrowser(context.Context, ProductCaptureBrowserRuntimeInvocation) (core.RuntimeExecutionResult, error)
}

type SandboxRuntimeProductCaptureBrowserAdapter struct {
	Runtime computecontainer.SandboxRuntime
}

func NewProductCaptureBrowserInvocation(opts ProductCaptureBrowserInvocationOptions) (ProductCaptureBrowserRuntimeInvocation, error) {
	if strings.TrimSpace(opts.Workspace) == "" {
		return ProductCaptureBrowserRuntimeInvocation{}, errors.New("workspace is required")
	}
	if err := opts.Workload.Validate(); err != nil {
		return ProductCaptureBrowserRuntimeInvocation{}, err
	}
	payload := ProductCaptureProviderRequest{Workload: opts.Workload}
	input, err := json.Marshal(payload)
	if err != nil {
		return ProductCaptureBrowserRuntimeInvocation{}, fmt.Errorf("marshal product capture runtime input: %w", err)
	}
	runtimeReq := core.RuntimeExecutionRequest{
		ProtocolVersion: core.Version,
		TaskID:          opts.TaskID,
		LeaseID:         opts.LeaseID,
		WorkloadKind:    core.WorkloadProductCapture,
		Operation:       ProductCaptureBrowserOperationCapture,
		Input:           input,
		Limits:          opts.Limits,
	}
	if err := runtimeReq.Validate(); err != nil {
		return ProductCaptureBrowserRuntimeInvocation{}, err
	}
	return ProductCaptureBrowserRuntimeInvocation{
		Request:   runtimeReq,
		Image:     opts.Image,
		Workspace: opts.Workspace,
		Network:   opts.Network,
		Timeout:   opts.Timeout,
	}, nil
}

func (a SandboxRuntimeProductCaptureBrowserAdapter) RunProductCaptureBrowser(ctx context.Context, invocation ProductCaptureBrowserRuntimeInvocation) (core.RuntimeExecutionResult, error) {
	if a.Runtime == nil {
		return core.RuntimeExecutionResult{}, errors.New("sandbox runtime is required")
	}
	if err := invocation.Request.Validate(); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	if invocation.Request.WorkloadKind != core.WorkloadProductCapture {
		return core.RuntimeExecutionResult{}, fmt.Errorf("workload kind %q is not supported by product capture browser runtime", invocation.Request.WorkloadKind)
	}
	if invocation.Request.Operation != ProductCaptureBrowserOperationCapture {
		return core.RuntimeExecutionResult{}, fmt.Errorf("operation %q is not supported by product capture browser runtime", invocation.Request.Operation)
	}
	if len(invocation.Request.Input) == 0 {
		return core.RuntimeExecutionResult{}, errors.New("product capture runtime input is required")
	}
	var payload ProductCaptureProviderRequest
	if err := json.Unmarshal(invocation.Request.Input, &payload); err != nil {
		return core.RuntimeExecutionResult{}, fmt.Errorf("decode product capture runtime input: %w", err)
	}
	if err := payload.Workload.Validate(); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	requestPath := filepath.Join(invocation.Workspace, ProductCaptureRequestPath)
	if err := WriteStrictJSON(requestPath, payload); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	if err := a.Runtime.Available(ctx); err != nil {
		return core.RuntimeExecutionResult{}, fmt.Errorf("product capture sandbox runtime unavailable: %w", err)
	}
	timeout := invocation.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	started := time.Now().UTC()
	sandboxResult, err := a.Runtime.Run(ctx, computecontainer.SandboxRunRequest{
		Image:          invocation.Image,
		Command:        ProductCaptureCommand(),
		Workspace:      invocation.Workspace,
		WorkingDir:     "/workspace",
		Network:        invocation.Network,
		RuntimeName:    "",
		RunAsRoot:      false,
		WritableRootFS: false,
		Timeout:        timeout,
		Limits:         invocation.Request.Limits,
	})
	finished := time.Now().UTC()
	return core.RuntimeExecutionResult{
		StartedAt:     started,
		FinishedAt:    finished,
		ExitCode:      sandboxResult.ExitCode,
		Stdout:        sandboxResult.Stdout,
		Stderr:        sandboxResult.Stderr,
		ResourceUsage: sandboxResult.ResourceUsage,
	}, err
}

type ProductCaptureProviderRequest struct {
	Workload core.ProductCaptureWorkload `json:"workload"`
}

func ProductCaptureCommand() []string {
	return []string{
		"/workspace/" + ProductCaptureProviderBinaryPath,
		"--request", "/workspace/" + ProductCaptureRequestPath,
		"--output", "/workspace/" + ProductCaptureSnapshotPath,
	}
}

type RuntimeAdapterCatalogDocument struct {
	Version                   string                       `json:"version"`
	ProtocolVersion           string                       `json:"protocol_version"`
	Adapters                  []RuntimeAdapterCatalogEntry `json:"adapters"`
	HostOwnedResponsibilities []string                     `json:"host_owned_responsibilities"`
}

func (d RuntimeAdapterCatalogDocument) Validate() error {
	var errs []error
	if d.Version == "" {
		errs = append(errs, errors.New("version is required"))
	}
	if d.ProtocolVersion != core.Version {
		errs = append(errs, fmt.Errorf("protocol_version = %q, want %q", d.ProtocolVersion, core.Version))
	}
	if len(d.Adapters) == 0 {
		errs = append(errs, errors.New("at least one adapter is required"))
	}
	for i, adapter := range d.Adapters {
		if err := adapter.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("adapters[%d]: %w", i, err))
		}
	}
	if len(d.HostOwnedResponsibilities) == 0 {
		errs = append(errs, errors.New("host_owned_responsibilities is required"))
	}
	return errors.Join(errs...)
}

type RuntimeAdapterCatalogEntry struct {
	AdapterID           string                      `json:"adapter_id"`
	Operation           string                      `json:"operation"`
	Kinds               []core.RuntimeAdapterKind   `json:"kinds"`
	WorkloadKinds       []core.WorkloadKind         `json:"workload_kinds"`
	RuntimeProfiles     []core.RuntimeProfile       `json:"runtime_profiles"`
	WorkspacePolicy     core.RuntimeWorkspacePolicy `json:"workspace_policy"`
	ConformanceProfiles []string                    `json:"conformance_profiles"`
}

func (e RuntimeAdapterCatalogEntry) Validate() error {
	var errs []error
	if e.AdapterID == "" {
		errs = append(errs, errors.New("adapter_id is required"))
	}
	if e.Operation == "" {
		errs = append(errs, errors.New("operation is required"))
	}
	if len(e.Kinds) == 0 {
		errs = append(errs, errors.New("kinds is required"))
	}
	if len(e.WorkloadKinds) == 0 {
		errs = append(errs, errors.New("workload_kinds is required"))
	}
	if len(e.RuntimeProfiles) == 0 {
		errs = append(errs, errors.New("runtime_profiles is required"))
	}
	if e.WorkspacePolicy == "" {
		errs = append(errs, errors.New("workspace_policy is required"))
	}
	if len(e.ConformanceProfiles) == 0 {
		errs = append(errs, errors.New("conformance_profiles is required"))
	}
	return errors.Join(errs...)
}

func (e RuntimeAdapterCatalogEntry) Contract(descriptor core.RuntimeDescriptor) core.RuntimeAdapterContract {
	if descriptor.Name == "" {
		descriptor.Name = e.AdapterID
	}
	return core.RuntimeAdapterContract{
		ProtocolVersion:     core.Version,
		AdapterID:           e.AdapterID,
		Descriptor:          descriptor,
		Kinds:               slices.Clone(e.Kinds),
		WorkloadKinds:       slices.Clone(e.WorkloadKinds),
		RuntimeProfiles:     slices.Clone(e.RuntimeProfiles),
		WorkspacePolicy:     e.WorkspacePolicy,
		ConformanceProfiles: slices.Clone(e.ConformanceProfiles),
	}
}

func WASMComponentContract(descriptor core.RuntimeDescriptor) core.RuntimeAdapterContract {
	if descriptor.Name == "" {
		descriptor.Name = WASMComponentProviderName
	}
	return core.RuntimeAdapterContract{
		ProtocolVersion:     core.Version,
		AdapterID:           WASMComponentProviderName,
		Descriptor:          descriptor,
		Kinds:               []core.RuntimeAdapterKind{core.RuntimeAdapterExecution},
		WorkloadKinds:       []core.WorkloadKind{core.WorkloadWASMComponent, core.WorkloadProvider},
		RuntimeProfiles:     []core.RuntimeProfile{core.RuntimeProfileWASMComponent},
		WorkspacePolicy:     core.RuntimeWorkspaceRequired,
		ConformanceProfiles: []string{"wasm-component-v1"},
	}
}

func ProductCaptureBrowserContract(descriptor core.RuntimeDescriptor) core.RuntimeAdapterContract {
	if descriptor.Name == "" {
		descriptor.Name = ProductCaptureBrowserProviderName
	}
	return core.RuntimeAdapterContract{
		ProtocolVersion:     core.Version,
		AdapterID:           ProductCaptureBrowserProviderName,
		Descriptor:          descriptor,
		Kinds:               []core.RuntimeAdapterKind{core.RuntimeAdapterExecution},
		WorkloadKinds:       []core.WorkloadKind{core.WorkloadProductCapture},
		RuntimeProfiles:     []core.RuntimeProfile{core.RuntimeProfileBrowserWorker, core.RuntimeProfileSandboxedOCI},
		WorkspacePolicy:     core.RuntimeWorkspaceRequired,
		ConformanceProfiles: []string{"product-capture-browser-v1"},
	}
}

func SHA256Ref(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func BoundedWASMStdin(input json.RawMessage) *bytes.Reader {
	return bytes.NewReader(input)
}

func WASMMemoryLimitPages(memoryBytes int64) uint32 {
	if memoryBytes <= 0 {
		memoryBytes = defaultWASMComponentMemoryBytes
	}
	pages := (memoryBytes + 65535) / 65536
	if pages < 1 {
		return 1
	}
	if pages > int64(maxWASMMemoryPages) {
		return maxWASMMemoryPages
	}
	return uint32(pages)
}

func WriteStrictJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func resolveInside(root, name string) (string, error) {
	root = filepath.Clean(root)
	candidate := filepath.Clean(filepath.Join(root, name))
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", err
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes workspace: %s", name)
	}
	return candidate, nil
}

func validateComponentRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("required")
	}
	if strings.ContainsAny(ref, "\t\r\n \x00") {
		return errors.New("must not contain whitespace or NUL")
	}
	switch {
	case strings.HasPrefix(ref, "artifact://"), strings.HasPrefix(ref, "provider://"):
		return nil
	default:
		return errors.New("must use artifact:// or provider://")
	}
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

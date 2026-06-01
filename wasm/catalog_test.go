package wasm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeAdaptersCatalogValidates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "runtime-adapters.json"))
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var doc RuntimeAdapterCatalogDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("catalog invalid: %v", err)
	}
}

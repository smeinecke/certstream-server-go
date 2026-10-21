package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateCTIndexFile_InitializesNilIndex(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: nil}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	err := m.createCTIndexFile(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if m.index == nil {
		t.Fatal("expected index to be initialized, but it is nil")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("expected file to exist, got read error: %v", readErr)
	}

	var parsed CTCertIndex
	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		t.Fatalf("expected valid JSON, got: %v", jsonErr)
	}

	if len(parsed) != 0 {
		t.Fatalf("expected empty index, got %d entries", len(parsed))
	}
}

func TestCreateCTIndexFile_WritesExistingIndexData(t *testing.T) {
	index := CTCertIndex{
		"https://ct.example.com/log": 42,
		"https://ct.other.com/log":   100,
	}
	m := &LogMetrics{metrics: make(CTMetrics), index: index}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	err := m.createCTIndexFile(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("expected file to exist, got read error: %v", readErr)
	}

	var parsed CTCertIndex
	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		t.Fatalf("expected valid JSON, got: %v", jsonErr)
	}

	for key, expectedVal := range index {
		gotVal, ok := parsed[key]
		if !ok {
			t.Errorf("expected key %q in file, but not found", key)
			continue
		}
		if gotVal != expectedVal {
			t.Errorf("for key %q: expected %d, got %d", key, expectedVal, gotVal)
		}
	}
}

func TestCreateCTIndexFile_ReturnsErrorForInvalidPath(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	// Use a path inside a non-existent directory to trigger os.Create failure.
	path := filepath.Join(t.TempDir(), "nonexistent", "ct_index.json")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid path, but did not panic")
		}
	}()

	_ = m.createCTIndexFile(path)
}

func TestLoadCTIndex_DoesNotDeadlockWhenFileMissing(t *testing.T) {
	metrics := LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	ctIndexPath := filepath.Join(t.TempDir(), "ct_index.json")
	writeErr := os.WriteFile(ctIndexPath, []byte("{}"), 0o644)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}

	done := make(chan struct{})
	go func() {
		metrics.LoadCTIndex(ctIndexPath)
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("LoadCTIndex appears to deadlock when index file is missing")
	}
}

func TestLoadCTIndex_CreatesFileWhenMissing(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	m.LoadCTIndex(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected LoadCTIndex to create the file when missing, but file does not exist")
	}

	if len(m.index) != 0 {
		t.Fatalf("expected empty index after loading missing file, got %d entries", len(m.index))
	}
}

func TestLoadCTIndex_LoadsValidFile(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	want := CTCertIndex{
		"https://ct.example.com/log": 42,
		"https://ct.other.com/log":   999,
	}
	data, marshalErr := json.Marshal(want)
	if marshalErr != nil {
		t.Fatalf("failed to marshal test data: %v", marshalErr)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m.LoadCTIndex(path)

	for url, expectedIdx := range want {
		got := m.GetCTIndex(url)
		if got != expectedIdx {
			t.Errorf("url %q: expected index %d, got %d", url, expectedIdx, got)
		}
	}
}

func TestLoadCTIndex_LoadsEmptyJSONFile(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m.LoadCTIndex(path)

	if len(m.index) != 0 {
		t.Fatalf("expected empty index, got %d entries", len(m.index))
	}
}

func TestLoadCTIndex_LoadsEmptyFile(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// An empty file is treated as corrupt - quarantined, empty index, no panic.
	m.LoadCTIndex(path)

	if len(m.index) != 0 {
		t.Fatalf("expected empty index after corrupt file, got %d entries", len(m.index))
	}

	if _, err := os.Stat(path + ".corrupt"); os.IsNotExist(err) {
		t.Fatal("expected empty file to be moved to .corrupt")
	}
}

func TestLoadCTIndex_OverwritesPreexistingIndex(t *testing.T) {
	m := &LogMetrics{
		metrics: make(CTMetrics),
		index:   CTCertIndex{"https://old.example.com/log": 1},
	}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	want := CTCertIndex{"https://new.example.com/log": 77}
	data, marshalErr := json.Marshal(want)
	if marshalErr != nil {
		t.Fatalf("failed to marshal test data: %v", marshalErr)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m.LoadCTIndex(path)

	if got := m.GetCTIndex("https://new.example.com/log"); got != 77 {
		t.Errorf("expected new entry with index 77, got %d", got)
	}
	if got := m.GetCTIndex("https://old.example.com/log"); got != 0 {
		t.Errorf("expected old entry to be gone (0), got %d", got)
	}
}

func TestLoadCTIndex_QuarantinesInvalidJSON(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// A corrupt index file must not panic the service - it is moved aside and
	// the index starts empty.
	m.LoadCTIndex(path)

	if len(m.index) != 0 {
		t.Fatalf("expected empty index after corrupt file, got %d entries", len(m.index))
	}

	if _, err := os.Stat(path + ".corrupt"); os.IsNotExist(err) {
		t.Fatal("expected corrupt file to be moved to .corrupt")
	}
}

func TestLoadCTIndex_RecoversFromBackup(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0o644); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	backup := CTCertIndex{"https://ct.example.com/log": 77}
	data, marshalErr := json.Marshal(backup)
	if marshalErr != nil {
		t.Fatalf("failed to marshal backup data: %v", marshalErr)
	}
	if err := os.WriteFile(path+".bak", data, 0o644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	m.LoadCTIndex(path)

	if got := m.GetCTIndex("https://ct.example.com/log"); got != 77 {
		t.Fatalf("expected index 77 recovered from backup, got %d", got)
	}
}

func TestLoadCTIndex_CorruptJSONPartialDataNotMerged(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	// Truncated mid-object: unmarshal may populate some entries before failing.
	if err := os.WriteFile(path, []byte(`{"https://a.example.com": 5, "https://b`), 0o644); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	backup := CTCertIndex{"https://ct.example.com/log": 77}
	data, marshalErr := json.Marshal(backup)
	if marshalErr != nil {
		t.Fatalf("failed to marshal backup data: %v", marshalErr)
	}
	if err := os.WriteFile(path+".bak", data, 0o644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	m.LoadCTIndex(path)

	// The restored index must contain only backup data - no partial entries
	// from the failed unmarshal may leak through.
	if got := m.GetCTIndex("https://a.example.com"); got != 0 {
		t.Fatalf("partial entry leaked into restored index: got %d", got)
	}
	if got := m.GetCTIndex("https://ct.example.com/log"); got != 77 {
		t.Fatalf("expected index 77 recovered from backup, got %d", got)
	}
}

func TestSaveCertIndexes_RotatesBackup(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	m.SetCTIndex("https://ct.example.com/log", 42)
	if err := m.SaveCertIndexes(path); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	m.SetCTIndex("https://ct.example.com/log", 84)
	if err := m.SaveCertIndexes(path); err != nil {
		t.Fatalf("second save failed: %v", err)
	}

	// The .bak file must hold the previous generation.
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("expected .bak file after second save: %v", err)
	}

	var restored CTCertIndex
	if jsonErr := json.Unmarshal(backup, &restored); jsonErr != nil {
		t.Fatalf("backup file is not valid JSON: %v", jsonErr)
	}
	if restored["https://ct.example.com/log"] != 42 {
		t.Fatalf("expected backup to contain index 42, got %d", restored["https://ct.example.com/log"])
	}

	// And the main file must hold the newest generation.
	mainData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read main index file: %v", err)
	}
	var current CTCertIndex
	if jsonErr := json.Unmarshal(mainData, &current); jsonErr != nil {
		t.Fatalf("main file is not valid JSON: %v", jsonErr)
	}
	if current["https://ct.example.com/log"] != 84 {
		t.Fatalf("expected main file to contain index 84, got %d", current["https://ct.example.com/log"])
	}
}

func TestLoadCTIndex_PanicsWhenDirectoryMissing(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "nonexistent", "ct_index.json")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when index file directory is missing, but did not panic")
		}
	}()

	m.LoadCTIndex(path)
}

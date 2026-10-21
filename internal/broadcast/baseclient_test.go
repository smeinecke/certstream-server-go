package broadcast

import "testing"

func TestBaseClientCloseIsSafeForNilChannelsAndRepeatedCalls(t *testing.T) {
	client := &BaseClient{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BaseClient.Close() panicked: %v", r)
		}
	}()

	client.Close()
	client.Close()
}

// TestBaseClientWriteCountsSkippedCerts verifies the non-blocking Write drops
// messages on a full channel and counts them in skippedCerts.
func TestBaseClientWriteCountsSkippedCerts(t *testing.T) {
	client := &BaseClient{
		broadcastChan: make(chan []byte, 1),
		name:          "test-client",
	}

	client.Write([]byte("first"))
	if got := client.SkippedCerts(); got != 0 {
		t.Fatalf("SkippedCerts = %d, want 0 after successful write", got)
	}

	// Channel is now full - subsequent writes are dropped and counted.
	client.Write([]byte("second"))
	client.Write([]byte("third"))

	if got := client.SkippedCerts(); got != 2 {
		t.Fatalf("SkippedCerts = %d, want 2", got)
	}

	if got := <-client.broadcastChan; string(got) != "first" {
		t.Fatalf("broadcast channel got %q, want %q", got, "first")
	}
}

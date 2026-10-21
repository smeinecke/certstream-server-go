package broadcast

import (
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
)

func newDispatcherTestWebsocketClient(name string) *WebsocketClient {
	return &WebsocketClient{
		hostIP:   "127.0.0.1",
		hostPort: "12345",
		BaseClient: &BaseClient{
			broadcastChan: make(chan []byte, 1),
			name:          name,
			subType:       SubTypeFull,
		},
	}
}

func TestDispatcherRegisterClientTwice(t *testing.T) {
	d := &Dispatcher{}
	client := newDispatcherTestWebsocketClient("client-1")

	d.RegisterClient(client)
	d.RegisterClient(client)

	if got := len(d.clients); got != 1 {
		t.Fatalf("expected 1 registered client after duplicate register, got %d", got)
	}
}

func TestDispatcherUnregisterWebsocketClient(t *testing.T) {
	d := &Dispatcher{}
	client := newDispatcherTestWebsocketClient("client-1")

	d.RegisterClient(client)
	if got := len(d.clients); got != 1 {
		t.Fatalf("expected 1 registered client, got %d", got)
	}

	d.UnregisterClient(client)
	if got := len(d.clients); got != 0 {
		t.Fatalf("expected 0 registered clients after unregister, got %d", got)
	}
}

func TestDispatcherUnregisterWebsocketClientDoesNotPanicOnNilStopChan(t *testing.T) {
	d := &Dispatcher{}
	client := newDispatcherTestWebsocketClient("client-2")

	d.RegisterClient(client)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unregistering websocket client panicked: %v", r)
		}
	}()

	d.UnregisterClient(client)
}

func newSubtypeTestClient(name string, subType SubscriptionType) *BaseClient {
	return &BaseClient{
		broadcastChan: make(chan []byte, 4),
		name:          name,
		subType:       subType,
	}
}

// TestBroadcasterDispatchesBySubtype verifies each client receives the JSON
// representation matching its subscription type, and that dispatch works when
// only a subset of stream types has subscribers (lazy marshal).
func TestBroadcasterDispatchesBySubtype(t *testing.T) {
	entry := models.Entry{
		MessageType: "certificate_update",
		Data: models.Data{
			CertIndex: 42,
			// Chain and AsDER ensure the lite/full representations differ - so
			// the test catches a client receiving the wrong subtype payload.
			Chain: []models.LeafCert{{SerialNumber: "AABB"}},
			LeafCert: models.LeafCert{
				AllDomains: []string{"example.com"},
				AsDER:      "ZGVy",
			},
		},
	}

	cases := []struct {
		name     string
		subTypes []SubscriptionType
	}{
		{"lite only", []SubscriptionType{SubTypeLite}},
		{"full only", []SubscriptionType{SubTypeFull}},
		{"domain only", []SubscriptionType{SubTypeDomain}},
		{"all subtypes", []SubscriptionType{SubTypeLite, SubTypeFull, SubTypeDomain}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Dispatcher{MessageQueue: make(chan models.Entry, 1)}
			d.Start()

			clients := make([]*BaseClient, len(tc.subTypes))
			want := map[SubscriptionType][]byte{
				SubTypeLite:   entry.JSONLite(),
				SubTypeFull:   entry.JSON(),
				SubTypeDomain: entry.JSONDomains(),
			}

			// Sanity: the three representations must actually differ, or the
			// test cannot detect wrong-subtype routing.
			if string(want[SubTypeLite]) == string(want[SubTypeFull]) {
				t.Fatal("lite and full representations are identical - fixture is broken")
			}

			for i, st := range tc.subTypes {
				clients[i] = newSubtypeTestClient("c", st)
				d.RegisterClient(clients[i])
			}

			d.MessageQueue <- entry

			for i, st := range tc.subTypes {
				select {
				case got := <-clients[i].broadcastChan:
					if string(got) != string(want[st]) {
						t.Fatalf("client %d (subtype %d) got %q, want %q", i, st, got, want[st])
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("client %d (subtype %d) received nothing", i, st)
				}
			}
		})
	}
}

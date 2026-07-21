package fleet

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// scriptedCeremony replays a fixed sequence of ceremony event kinds, then EOF.
type scriptedCeremony struct {
	kinds []cryptosv1.CeremonyEventKind
	i     int
}

func (s *scriptedCeremony) Recv() (*cryptosv1.StartCeremonyResponse, error) {
	if s.i >= len(s.kinds) {
		return nil, io.EOF
	}
	k := s.kinds[s.i]
	s.i++
	return &cryptosv1.StartCeremonyResponse{
		Event: &cryptosv1.CeremonyEvent{Kind: k, Ts: timestamppb.Now()},
	}, nil
}

// collectSink records every streamed phase for assertion.
type collectSink struct {
	phases []string
	done   bool
}

func (c *collectSink) send(phase, _ string, done bool) error {
	c.phases = append(c.phases, phase)
	if done {
		c.done = true
	}
	return nil
}

func adoptConfig() *cryptosv1.MachineConfig {
	return &cryptosv1.MachineConfig{
		Metadata: &cryptosv1.Metadata{Name: "new-node"},
		Role:     &cryptosv1.Role{Kind: "root"},
	}
}

func TestPreviewAdoption_Admin_ReturnsFingerprint(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(
		func(endpoint string) (string, string, error) {
			return "abc123", "CN=maintenance", nil
		}, nil)

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.PreviewAdoption(ctx, connect.NewRequest(&fleetv1.PreviewAdoptionRequest{Endpoint: "node:4443"}))
	if err != nil {
		t.Fatalf("PreviewAdoption(admin) error = %v", err)
	}
	if resp.Msg.GetCertSha256() != "abc123" || resp.Msg.GetSubject() != "CN=maintenance" {
		t.Errorf("preview = %+v, want abc123 / CN=maintenance", resp.Msg)
	}
}

func TestPreviewAdoption_OperatorDenied(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(
		func(string) (string, string, error) { return "x", "y", nil }, nil)
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.PreviewAdoption(ctx, connect.NewRequest(&fleetv1.PreviewAdoptionRequest{Endpoint: "n:1"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestRunAdoption_HappyPath_StreamsPhasesRegistersAndAudits(t *testing.T) {
	st := memory.New(nil)
	mconn := &fakeConn{
		applyConfigResp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true, Generation: 1},
		status:          &cryptosv1.GetStatusResponse{},
		ceremonyStream: &scriptedCeremony{kinds: []cryptosv1.CeremonyEventKind{
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED,
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED,
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		}},
	}
	svc := New(st, dialFor(nil)).WithAdoption(nil,
		func(endpoint, pin string) (NodeConn, error) { return mconn, nil })

	// Shrink the reboot timing so the bounded wait is fast in the test.
	restore := setRebootTiming(5*time.Millisecond, 1*time.Millisecond, 1*time.Millisecond)
	defer restore()

	sink := &collectSink{}
	err := svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
		Endpoint: "node:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
	}, sink.send)
	if err != nil {
		t.Fatalf("runAdoption happy path error = %v", err)
	}

	if !sink.done {
		t.Error("adoption did not stream a terminal done phase")
	}
	if !containsPhase(sink.phases, phaseApplyingConfig) ||
		!containsPhase(sink.phases, phaseAwaitingReboot) ||
		!containsPhase(sink.phases, phaseCeremony) ||
		!containsPhase(sink.phases, phaseEstablished) {
		t.Errorf("phases = %v, want applying-config/awaiting-reboot/ceremony/established", sink.phases)
	}
	if got := mconn.gotCeremonyYAML; len(got) == 0 {
		t.Error("StartCeremony was not given the config YAML")
	}

	if _, ok := st.Node("new-node"); !ok {
		t.Error("adopted node was not registered in the inventory")
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-adopted" {
		t.Fatalf("audit = %+v, want one node-adopted event", audit)
	}
}

func TestRunAdoption_RebootNeverReturns_StreamsErrorPhase_NoHang(t *testing.T) {
	st := memory.New(nil)
	// The first dial applies the config fine; every re-dial after the reboot
	// returns a conn whose GetStatus errors, so the node never confirms it is
	// back. The bounded reboot wait must expire and stream an error phase
	// rather than blocking forever.
	var dials int
	dial := func(endpoint, pin string) (NodeConn, error) {
		dials++
		if dials == 1 {
			return &fakeConn{applyConfigResp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true}}, nil
		}
		return &fakeConn{err: errors.New("node down")}, nil
	}
	svc := New(st, dialFor(nil)).WithAdoption(nil, dial)

	restore := setRebootTiming(10*time.Millisecond, 2*time.Millisecond, 1*time.Millisecond)
	defer restore()

	sink := &collectSink{}
	done := make(chan error, 1)
	go func() {
		done <- svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
			Endpoint: "node:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
		}, sink.send)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runAdoption returned nil on a node that never rebooted, want an error")
		}
		requireConnectCode(t, err, connect.CodeDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("runAdoption hung waiting for a reboot that never returns")
	}

	if !containsPhase(sink.phases, phaseError) {
		t.Errorf("phases = %v, want a terminal error phase", sink.phases)
	}
	if _, ok := st.Node("new-node"); ok {
		t.Error("a failed adoption registered the node anyway")
	}
	if len(st.Audit()) != 0 {
		t.Error("a failed adoption wrote a node-adopted audit event")
	}
}

func TestRunAdoption_MissingPin_InvalidArgument(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(string, string) (NodeConn, error) { return &fakeConn{}, nil })
	sink := &collectSink{}
	err := svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
		Endpoint: "node:4443", Config: adoptConfig(),
	}, sink.send)
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestAdoptNode_OperatorDenied(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(string, string) (NodeConn, error) { return &fakeConn{}, nil })
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	// requireAdmin runs before any streaming, so a nil stream is never touched.
	err := svc.AdoptNode(ctx, connect.NewRequest(&fleetv1.AdoptNodeRequest{
		Endpoint: "n:1", PinnedCertSha256: "p", Config: adoptConfig(),
	}), nil)
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func containsPhase(phases []string, want string) bool {
	for _, p := range phases {
		if p == want {
			return true
		}
	}
	return false
}

// setRebootTiming overrides the bounded reboot timing for a test and returns a
// restore func.
func setRebootTiming(wait, poll, grace time.Duration) func() {
	ow, op, og := rebootWait, rebootPollGap, rebootPollGrace
	rebootWait, rebootPollGap, rebootPollGrace = wait, poll, grace
	return func() { rebootWait, rebootPollGap, rebootPollGrace = ow, op, og }
}

package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestApprove(t *testing.T) {
	m := NewManager(time.Second, 10)
	req, ch, err := m.Create("alice", "sshd", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Decide(req.ID, Approved); err != nil {
		t.Fatal(err)
	}
	if got := m.Wait(context.Background(), req, ch); got != Approved {
		t.Fatalf("got %s", got)
	}
	if err := m.Decide(req.ID, Approved); !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate decision: %v", err)
	}
}

func TestDeny(t *testing.T) {
	m := NewManager(time.Second, 10)
	req, ch, _ := m.Create("alice", "sshd", "")
	if err := m.Decide(req.ID, Denied); err != nil {
		t.Fatal(err)
	}
	if got := m.Wait(context.Background(), req, ch); got != Denied {
		t.Fatal(got)
	}
}

func TestExpire(t *testing.T) {
	m := NewManager(15*time.Millisecond, 10)
	req, ch, _ := m.Create("alice", "sshd", "")
	if got := m.Wait(context.Background(), req, ch); got != Expired {
		t.Fatal(got)
	}
	if err := m.Decide(req.ID, Approved); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestCancel(t *testing.T) {
	m := NewManager(time.Second, 10)
	req, ch, _ := m.Create("alice", "sshd", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := m.Wait(ctx, req, ch); got != Canceled {
		t.Fatal(got)
	}
	if len(m.Pending()) != 0 {
		t.Fatal("request still pending")
	}
}

func TestLimit(t *testing.T) {
	m := NewManager(time.Second, 1)
	_, _, _ = m.Create("alice", "sshd", "")
	if _, _, err := m.Create("bob", "sshd", ""); !errors.Is(err, ErrTooMany) {
		t.Fatal(err)
	}
}

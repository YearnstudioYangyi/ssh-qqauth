package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("approval request not found or already completed")
	ErrTooMany  = errors.New("too many pending requests")
)

type Decision string

const (
	Approved Decision = "approved"
	Denied   Decision = "denied"
	Expired  Decision = "expired"
	Canceled Decision = "canceled"
)

type Request struct {
	ID         string    `json:"id"`
	User       string    `json:"user"`
	Service    string    `json:"service"`
	RemoteHost string    `json:"remote_host"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type entry struct {
	request Request
	result  chan Decision
}

type Manager struct {
	mu      sync.Mutex
	pending map[string]*entry
	timeout time.Duration
	limit   int
}

func NewManager(timeout time.Duration, limit int) *Manager {
	if timeout <= 0 {
		panic("approval timeout must be positive")
	}
	if limit <= 0 {
		panic("approval limit must be positive")
	}
	return &Manager{pending: make(map[string]*entry), timeout: timeout, limit: limit}
}

func (m *Manager) Create(user, service, remoteHost string) (Request, <-chan Decision, error) {
	if user == "" || service == "" {
		return Request{}, nil, errors.New("user and service are required")
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return Request{}, nil, err
	}
	now := time.Now()
	req := Request{ID: hex.EncodeToString(bytes[:]), User: user, Service: service, RemoteHost: remoteHost, CreatedAt: now, ExpiresAt: now.Add(m.timeout)}
	e := &entry{request: req, result: make(chan Decision, 1)}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) >= m.limit {
		return Request{}, nil, ErrTooMany
	}
	m.pending[req.ID] = e
	return req, e.result, nil
}

func (m *Manager) Decide(id string, decision Decision) error {
	if decision != Approved && decision != Denied {
		return errors.New("invalid decision")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.pending[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.pending, id)
	if !time.Now().Before(e.request.ExpiresAt) {
		e.result <- Expired
		return ErrNotFound
	}
	e.result <- decision
	return nil
}

func (m *Manager) Cancel(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.pending[id]; ok {
		delete(m.pending, id)
		e.result <- Canceled
	}
}

func (m *Manager) Wait(ctx context.Context, req Request, result <-chan Decision) Decision {
	remaining := time.Until(req.ExpiresAt)
	if remaining <= 0 {
		m.Cancel(req.ID)
		return Expired
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case decision := <-result:
		return decision
	case <-ctx.Done():
		m.Cancel(req.ID)
		return Canceled
	case <-timer.C:
		// A decision that completed before the deadline may already be buffered.
		select {
		case decision := <-result:
			return decision
		default:
		}
		m.Cancel(req.ID)
		return Expired
	}
}

func (m *Manager) Pending() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, 0, len(m.pending))
	for _, e := range m.pending {
		if time.Now().Before(e.request.ExpiresAt) {
			out = append(out, e.request)
		}
	}
	return out
}

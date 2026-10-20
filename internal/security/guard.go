package security

import (
	"net"
	"os/user"
	"strings"
	"sync"
	"time"

	"example.com/qqauth/internal/model"
)

type BanRecord struct {
	IP        string
	Reason    string
	BannedAt  time.Time
	ExpiresAt time.Time
}

type Guard struct {
	mu sync.Mutex

	// 是否启用 PIN 码校验
	enablePIN bool
	// 预期约定的 PIN 码
	expectedPIN string

	// 当前活跃请求的子网锁集合，防止同一子网并发爆破
	activeSubnets map[string]struct{}

	// IP 封禁记录: IP -> BanRecord
	bannedIPs map[string]*BanRecord

	// IP 访问/失败时间戳记录: IP -> []time.Time (滑动窗口)
	attempts map[string][]time.Time

	// 频控配置
	rateWindow  time.Duration // 统计窗口，例如 1 分钟
	maxAttempts int           // 窗口内最大失败次数，例如 3 次
	banDuration time.Duration // 默认封禁时长，例如 30 分钟
}

func NewGuard(enablePIN bool, expectedPIN string) *Guard {
	if expectedPIN == "" {
		expectedPIN = "123456" // 默认约定 PIN 码
	}
	return &Guard{
		enablePIN:     enablePIN,
		expectedPIN:   expectedPIN,
		activeSubnets: make(map[string]struct{}),
		bannedIPs:     make(map[string]*BanRecord),
		attempts:      make(map[string][]time.Time),
		rateWindow:    1 * time.Minute,
		maxAttempts:   3,
		banDuration:   30 * time.Minute,
	}
}

// SubnetKey 获取 IP 对应的网段 key（IPv4 获取 /24 段，IPv6 获取 /64，本地返回 local）
func SubnetKey(rawIP string) string {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" || rawIP == "127.0.0.1" || rawIP == "::1" || rawIP == "localhost" {
		return "local"
	}

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return rawIP
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		// 取 /24 子网
		mask := net.CIDRMask(24, 32)
		network := ipv4.Mask(mask)
		return network.String() + "/24"
	}

	// IPv6 取 /64
	mask := net.CIDRMask(64, 128)
	network := ip.Mask(mask)
	return network.String() + "/64"
}

// TryAcquireSubnet 尝试获取同 IP 段互斥锁，成功返回 release 函数，失败返回 nil, false
func (g *Guard) TryAcquireSubnet(ip string) (func(), bool) {
	key := SubnetKey(ip)
	// 本地连接不互斥
	if key == "local" {
		return func() {}, true
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.activeSubnets[key]; exists {
		return nil, false
	}

	g.activeSubnets[key] = struct{}{}
	released := false
	release := func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !released {
			delete(g.activeSubnets, key)
			released = true
		}
	}
	return release, true
}

// CheckUserExists 检查目标用户在当前系统中是否存在
func (g *Guard) CheckUserExists(username string) bool {
	if username == "" {
		return false
	}
	_, err := user.Lookup(username)
	return err == nil
}

// ValidatePIN 校验 PIN 码是否匹配预置约定密码
func (g *Guard) ValidatePIN(pin string) bool {
	if !g.enablePIN {
		return true
	}
	return pin == g.expectedPIN
}

// IsBanned 检查 IP 是否被封禁（自动清理过期）
func (g *Guard) IsBanned(rawIP string) (bool, *BanRecord) {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" {
		return false, nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	record, exists := g.bannedIPs[rawIP]
	if !exists {
		return false, nil
	}

	if time.Now().After(record.ExpiresAt) {
		delete(g.bannedIPs, rawIP)
		return false, nil
	}

	return true, record
}

// Ban 封禁指定 IP
func (g *Guard) Ban(rawIP string, reason string, duration time.Duration) *BanRecord {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" {
		return nil
	}
	if duration <= 0 {
		duration = g.banDuration
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	record := &BanRecord{
		IP:        rawIP,
		Reason:    reason,
		BannedAt:  now,
		ExpiresAt: now.Add(duration),
	}
	g.bannedIPs[rawIP] = record
	delete(g.attempts, rawIP) // 封禁后清理尝试记录
	return record
}

// Unban 手动解封 IP
func (g *Guard) Unban(rawIP string) bool {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.bannedIPs[rawIP]; exists {
		delete(g.bannedIPs, rawIP)
		delete(g.attempts, rawIP)
		return true
	}
	return false
}

// RecordFailure 记录一次失败尝试，若 1 分钟内达到阈值则自动封禁，返回被封禁记录（若未触发返回 nil）
func (g *Guard) RecordFailure(rawIP string, reason string) *BanRecord {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-g.rateWindow)

	// 滑动窗口清理过期尝试
	var validAttempts []time.Time
	for _, t := range g.attempts[rawIP] {
		if t.After(cutoff) {
			validAttempts = append(validAttempts, t)
		}
	}
	validAttempts = append(validAttempts, now)
	g.attempts[rawIP] = validAttempts

	// 判断是否超限
	if len(validAttempts) >= g.maxAttempts {
		record := &BanRecord{
			IP:        rawIP,
			Reason:    reason,
			BannedAt:  now,
			ExpiresAt: now.Add(g.banDuration),
		}
		g.bannedIPs[rawIP] = record
		delete(g.attempts, rawIP)
		return record
	}

	return nil
}

// ListBanned 获取当前所有有效封禁记录
func (g *Guard) ListBanned() []model.BanItem {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	var list []model.BanItem

	for ip, rec := range g.bannedIPs {
		if now.After(rec.ExpiresAt) {
			delete(g.bannedIPs, ip)
			continue
		}
		list = append(list, model.BanItem{
			IP:        rec.IP,
			Reason:    rec.Reason,
			BannedAt:  rec.BannedAt.Format(time.RFC3339),
			ExpiresAt: rec.ExpiresAt.Format(time.RFC3339),
		})
	}
	return list
}

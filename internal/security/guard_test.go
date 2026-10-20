package security

import (
	"testing"
	"time"
)

func TestSubnetKey(t *testing.T) {
	if SubnetKey("192.168.1.100") != "192.168.1.0/24" {
		t.Fatalf("expected 192.168.1.0/24, got %s", SubnetKey("192.168.1.100"))
	}
	if SubnetKey("192.168.1.50") != "192.168.1.0/24" {
		t.Fatalf("expected 192.168.1.0/24, got %s", SubnetKey("192.168.1.50"))
	}
	if SubnetKey("") != "local" || SubnetKey("127.0.0.1") != "local" {
		t.Fatalf("expected local for empty or 127.0.0.1")
	}
}

func TestSubnetMutex(t *testing.T) {
	g := NewGuard(true, "123456")

	// 第一次获取成功
	release1, ok := g.TryAcquireSubnet("10.0.0.5")
	if !ok || release1 == nil {
		t.Fatalf("expected acquire success")
	}

	// 同网段并发获取应该失败
	_, ok2 := g.TryAcquireSubnet("10.0.0.88")
	if ok2 {
		t.Fatalf("expected acquire fail for same subnet")
	}

	// 不同网段应该成功
	release3, ok3 := g.TryAcquireSubnet("10.0.1.5")
	if !ok3 || release3 == nil {
		t.Fatalf("expected acquire success for different subnet")
	}

	// 释放后再次获取同网段应该成功
	release1()
	release4, ok4 := g.TryAcquireSubnet("10.0.0.99")
	if !ok4 || release4 == nil {
		t.Fatalf("expected acquire success after release")
	}
	release3()
	release4()
}

func TestBanAndUnban(t *testing.T) {
	g := NewGuard(true, "123456")
	ip := "1.2.3.4"

	banned, _ := g.IsBanned(ip)
	if banned {
		t.Fatalf("should not be banned initially")
	}

	g.Ban(ip, "test ban", 1*time.Minute)
	banned, rec := g.IsBanned(ip)
	if !banned || rec == nil || rec.Reason != "test ban" {
		t.Fatalf("should be banned with reason 'test ban'")
	}

	list := g.ListBanned()
	if len(list) != 1 || list[0].IP != ip {
		t.Fatalf("ban list should contain %s", ip)
	}

	unbanned := g.Unban(ip)
	if !unbanned {
		t.Fatalf("unban should return true")
	}

	banned, _ = g.IsBanned(ip)
	if banned {
		t.Fatalf("should not be banned after unban")
	}
}

func TestRateLimitFailure(t *testing.T) {
	g := NewGuard(true, "123456")
	ip := "5.6.7.8"

	// 尝试第 1、2 次，不应被封禁
	if rec := g.RecordFailure(ip, "wrong pin"); rec != nil {
		t.Fatalf("should not ban after 1 attempt")
	}
	if rec := g.RecordFailure(ip, "wrong pin"); rec != nil {
		t.Fatalf("should not ban after 2 attempts")
	}

	// 第 3 次应触发封禁
	rec := g.RecordFailure(ip, "too many failures")
	if rec == nil {
		t.Fatalf("should ban after 3 attempts")
	}

	banned, _ := g.IsBanned(ip)
	if !banned {
		t.Fatalf("ip should be marked banned")
	}
}

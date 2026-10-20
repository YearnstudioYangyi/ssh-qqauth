package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"example.com/qqauth/internal/approval"
	"example.com/qqauth/internal/botipc"
	"example.com/qqauth/internal/config"
	"example.com/qqauth/internal/model"
	"example.com/qqauth/internal/security"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Load configuration failed: %v", err)
	}

	socketPath := cfg.AuthSocket
	botSocketPath := cfg.BotSocket

	// 兼容调试环境变量
	if os.Getenv("QQAUTH_DEV") == "1" {
		socketPath = "/tmp/qqauth-dev.sock"
		botSocketPath = "/tmp/botipc-dev.sock"
	}

	// 确保 socket 父目录存在
	for _, p := range []string{socketPath, botSocketPath} {
		dir := filepath.Dir(p)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Create socket dir %s failed: %v", dir, err)
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			log.Fatalf("Clean socket %s failed: %v", p, err)
		}
	}

	// 开始监听
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	_ = os.Chmod(socketPath, 0666) // 允许本地所有服务连接

	log.Printf("qqauthd listening on %s (PIN enabled: %v)", socketPath, cfg.EnablePIN)

	// 创建安全防护引擎
	guard := security.NewGuard(cfg.EnablePIN, cfg.PIN)

	// 创建审批管理器
	manager := approval.NewManager(time.Minute, 100)

	// 创建与QQ机器人框架的通信管理器
	server := botipc.NewServer(botSocketPath, manager, guard)
	if err := server.Listen(); err != nil {
		log.Fatalf("Listen bot ipc socket failed: %v", err)
	}
	_ = os.Chmod(botSocketPath, 0666)
	go server.Serve()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("New connection from %s", conn.RemoteAddr())
		go handleConnection(conn, manager, server, guard)
	}
}

func handleConnection(conn net.Conn, manager *approval.Manager, server *botipc.Server, guard *security.Guard) {
	defer conn.Close()

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(conn)
	var req model.Req
	if err := decoder.Decode(&req); err != nil {
		log.Printf("Handle connection failed: %v", err)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("Cancel deadline failed: %v", err)
		return
	}
	if req.Version != 1 {
		log.Printf("Unsupported protocol version: %d", req.Version)
		return
	}

	encoder := json.NewEncoder(conn)
	switch req.Type {
	case "ping":
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Printf("Set write deadline failed: %v", err)
			return
		}
		encoder.Encode(model.Resp{
			Version: 1,
			Type:    "pong",
		})

	case "auth_request":
		if req.Service == "" || req.User == "" {
			log.Printf("Request missing service or user")
			return
		}

		// 1. 检查 IP 是否被封禁（Shadow Ban: 故意慢速延时并静默返回失败，不产生任何审批）
		if banned, rec := guard.IsBanned(req.RemoteHost); banned {
			log.Printf("IP %s is currently banned (reason: %s), silently dropping request", req.RemoteHost, rec.Reason)
			time.Sleep(1 * time.Second) // Tarpit 缓兵拖延
			encoder.Encode(model.Resp{
				Version:  1,
				Type:     "auth_result",
				Approved: false,
			})
			return
		}

		// 2. 检查系统是否存在目标用户（非合法账户嗅探 -> 立即 Ban IP 并告警）
		if !guard.CheckUserExists(req.User) {
			log.Printf("User %s does not exist on system! Banning IP %s", req.User, req.RemoteHost)
			guard.Ban(req.RemoteHost, fmt.Sprintf("尝试登录不存在的系统用户: %s", req.User), 0)
			server.SendAlert(model.BotAlertMessage{
				AlertType: "user_not_found",
				IP:        req.RemoteHost,
				User:      req.User,
				Service:   req.Service,
				Reason:    fmt.Sprintf("探测不存在的系统账户: %s", req.User),
			})
			time.Sleep(500 * time.Millisecond)
			encoder.Encode(model.Resp{
				Version:  1,
				Type:     "auth_result",
				Approved: false,
			})
			return
		}

		// 3. 同 IP / 子网并发互斥控制（防止多线程并发穿透）
		releaseSubnet, ok := guard.TryAcquireSubnet(req.RemoteHost)
		if !ok {
			log.Printf("Subnet for IP %s already has an active request, rejecting concurrent request", req.RemoteHost)
			encoder.Encode(model.Resp{
				Version:  1,
				Type:     "auth_result",
				Approved: false,
				Message:  "Concurrent request blocked for this subnet",
			})
			return
		}
		defer releaseSubnet()

		// 4. 验证约定 PIN 码（防无差别爆破与 QQ 骚扰）
		if !guard.ValidatePIN(req.PIN) {
			log.Printf("Invalid PIN from IP %s for user %s", req.RemoteHost, req.User)
			if banRec := guard.RecordFailure(req.RemoteHost, "1分钟内多次输入错误PIN码"); banRec != nil {
				log.Printf("IP %s exceeded failure threshold, banned until %s", req.RemoteHost, banRec.ExpiresAt)
				server.SendAlert(model.BotAlertMessage{
					AlertType: "rate_limit_ban",
					IP:        req.RemoteHost,
					User:      req.User,
					Service:   req.Service,
					Reason:    "1分钟内多次输入错误PIN码，已自动封禁",
				})
			}
			time.Sleep(500 * time.Millisecond)
			encoder.Encode(model.Resp{
				Version:  1,
				Type:     "auth_result",
				Approved: false,
			})
			return
		}

		// 5. 创建新的批准请求
		r, ch, err := manager.Create(req.User, req.Service, req.RemoteHost)
		if err != nil {
			log.Printf("Failed when create new login request: %v", err)
			return
		}

		// 向 PAM 客户端返回本次请求信息（携带 ID）
		if err := encoder.Encode(model.AuthRequestInfo{
			Version: 1,
			Type:    "request_info",
			ID:      r.ID,
		}); err != nil {
			log.Printf("Send request info failed: %v", err)
			return
		}

		// 发起申请到 Bot
		if err := server.Send(r); err != nil {
			log.Printf("Send approval request to bot failed: %v", err)
		}

		// 等待结果
		ctx, cancel := context.WithCancel(context.Background())
		watchDone := make(chan struct{})
		stopWatch := make(chan struct{})
		go func() {
			defer close(watchDone)
			var buf [1]byte
			_, err := conn.Read(buf[:])
			select {
			case <-stopWatch:
				return
			default:
			}
			if err != nil {
				log.Printf("Client disconnect: %v", err)
			} else {
				log.Printf("Unexpected data after auth request")
			}
			cancel()
		}()

		decision := manager.Wait(ctx, r, ch)
		close(stopWatch)
		_ = conn.SetReadDeadline(time.Now())

		log.Printf("request %v finished: %v", r.ID, decision)

		// 6. 若管理员在 QQ 上明确点击【拒绝】-> 判定为非本人操作，直接封禁 IP 并发告警
		if decision == approval.Denied {
			log.Printf("Request %s explicitly denied by admin! Banning IP %s", r.ID, req.RemoteHost)
			guard.Ban(req.RemoteHost, "管理员在QQ上手动拒绝审批", 0)
			server.SendAlert(model.BotAlertMessage{
				AlertType: "denied_ban",
				IP:        req.RemoteHost,
				User:      req.User,
				Service:   req.Service,
				Reason:    "管理员手动拒绝了本次登录请求，已自动封禁该IP",
			})
		}

		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Printf("Set write deadline failed: %v", err)
			return
		}

		var s model.Resp
		s.Type = "auth_result"
		s.Version = 1
		s.Approved = (decision == approval.Approved)
		encoder.Encode(s)

	default:
		// 未知消息类型
	}
}

package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"time"

	"example.com/qqauth/internal/approval"
)

func main() {
	socketPath := "/tmp/qqauth-dev.sock"

	// 清理上次的socket文件
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	// 开始监听
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("qqauthd listening on %s", socketPath)

	// 创建管理器
	manager := approval.NewManager(time.Minute, 100)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("New connection from %s", conn.RemoteAddr())
		go handleConnection(conn, manager)
		// conn.Close()
	}
}

type Req struct {
	Version    uint   `json:"version"`
	Type       string `json:"type"`
	Service    string `json:"service"`
	User       string `json:"user"`
	RemoteHost string `json:"remote_host"`
}

type Resp struct {
	Version  uint   `json:"version"`
	Type     string `json:"type"`
	Approved bool   `json:"approved"`
}

func handleConnection(conn net.Conn, manager *approval.Manager) {
	defer conn.Close()
	// 设置超时
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// 创建JSON解码器, 确保自动获取完整的JSON后再进行解析
	decoder := json.NewDecoder(conn)
	var req Req
	if err := decoder.Decode(&req); err != nil {
		log.Printf("Handle connection failed: %v", err)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("Cancel deadline failed: %v", err)
		return
	}
	if req.Version != 1 {
		log.Printf("Connection upload a version that could be understood by server")
		return
	}
	encoder := json.NewEncoder(conn)
	switch req.Type {
	case "ping":
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Printf("Set write deadline failed: %v", err)
			return
		}
		s := Resp{
			Version: 1,
			Type:    "pong",
		}
		encoder.Encode(s)
	case "auth_request":
		if req.Service == "" || req.User == "" {
			log.Printf("Request need service and user")
			return
		}
		// 创建新的批准请求
		r, ch, err := manager.Create(req.User, req.Service, req.RemoteHost)
		if err != nil {
			log.Printf("Failed when create new login request: %v", err)
			return
		}
		// 等待结果
		ctx, cancel := context.WithCancel(context.Background())
		// 建立监测, 处理客户端主动断开连接的情况
		watchDone := make(chan struct{})
		stopWatch := make(chan struct{})
		go func() {
			defer close(watchDone)

			var buf [1]byte

			_, err := conn.Read(buf[:])
			// 判断是客户端断开还是超时清理
			select {
			case <-stopWatch:
				// 不需要处理
				return
			default:
			}

			if err != nil {
				log.Printf("Client disconnect: %v", err)
			} else {
				// 客户端再次发送了数据, 不符合要求
				log.Printf("unexpected data after auth request")
			}
			cancel()
		}()

		decision := manager.Wait(ctx, r, ch)
		// 让阻塞的Read结束
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			log.Printf("Stop Read() failed: %v", err)
			return
		}

		// log.Printf("auth request: service = %s user = %s remote_host = %s, request_id = %v", req.Service, req.User, req.RemoteHost, r.ID)
		log.Printf("request %v finished: %v", r.ID, decision)
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Printf("Set write deadline failed: %v", err)
			return
		}
		// 通知监控线程静默退出
		<-stopWatch
		var s Resp
		s.Type = "auth_result"
		s.Version = 1
		if decision == approval.Approved {
			s.Approved = true
		} else {
			s.Approved = false
		}
		encoder.Encode(s)
	default:
		// 未知消息类型
	}
}

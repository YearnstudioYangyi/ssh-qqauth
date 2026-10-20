package botipc

import (
	"fmt"
	"log"
	"net"
	"sync"

	"example.com/qqauth/internal/approval"
	"example.com/qqauth/internal/model"
	"example.com/qqauth/internal/security"
)

type Server struct {
	socketPath string
	listener   *net.UnixListener
	manager    *approval.Manager
	guard      *security.Guard
	connMu     sync.RWMutex
	connection *connection
}

func NewServer(socketPath string, manager *approval.Manager, guard *security.Guard) *Server {
	return &Server{
		socketPath: socketPath,
		manager:    manager,
		guard:      guard,
	}
}

// 准备监听器
func (s *Server) Listen() error {
	addr, err := net.ResolveUnixAddr("unix", s.socketPath)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

// 开始监听请求
func (s *Server) Serve() {
	if s.listener == nil {
		return
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Accept new connection from Bot IPC failed: %v", err)
			continue
		}
		con := newConnection(conn)
		s.connMu.Lock()
		s.connection = con
		s.connMu.Unlock()

		if err := con.Serve(s.handleResponse); err != nil {
			log.Printf("Bot IPC connection exit: %v", err)
		}

		s.connMu.Lock()
		if s.connection == con {
			s.connection = nil
		}
		s.connMu.Unlock()
	}
}

// SendMsg 发送任意出站消息给 Bot
func (s *Server) SendMsg(msg any) error {
	s.connMu.RLock()
	con := s.connection
	s.connMu.RUnlock()

	if con == nil {
		return fmt.Errorf("no active Bot IPC connection")
	}
	return con.Send(msg)
}

// Send 发送一个审批请求
func (s *Server) Send(req approval.Request) error {
	return s.SendMsg(model.BotIPCRequest{
		ID:         req.ID,
		Version:    "1",
		Service:    req.Service,
		User:       req.User,
		RemoteHost: req.RemoteHost,
	})
}

// SendAlert 发送安全告警
func (s *Server) SendAlert(alert model.BotAlertMessage) error {
	if alert.Version == "" {
		alert.Version = "1"
	}
	if alert.Type == "" {
		alert.Type = "alert"
	}
	return s.SendMsg(alert)
}

func (s *Server) handleResponse(resp model.BotIPCResponse) error {
	switch resp.Type {
	case "approve":
		if resp.ID == "" {
			return fmt.Errorf("approve command missing id")
		}
		if resp.Approval {
			return s.manager.Decide(resp.ID, approval.Approved)
		} else {
			return s.manager.Decide(resp.ID, approval.Denied)
		}

	case "ban_list":
		if s.guard == nil {
			return fmt.Errorf("guard is nil")
		}
		items := s.guard.ListBanned()
		return s.SendMsg(model.BotBanListResponse{
			Version: "1",
			Type:    "ban_list_resp",
			Items:   items,
		})

	case "unban":
		if s.guard == nil {
			return fmt.Errorf("guard is nil")
		}
		success := s.guard.Unban(resp.IP)
		msg := fmt.Sprintf("IP %s unbanned successfully", resp.IP)
		if !success {
			msg = fmt.Sprintf("IP %s was not in ban list", resp.IP)
		}
		return s.SendMsg(model.BotActionResponse{
			Version: "1",
			Type:    "action_resp",
			Action:  "unban",
			Success: success,
			Message: msg,
		})

	case "ban":
		if s.guard == nil {
			return fmt.Errorf("guard is nil")
		}
		reason := resp.Reason
		if reason == "" {
			reason = "Manually banned via Bot command"
		}
		rec := s.guard.Ban(resp.IP, reason, 0)
		return s.SendMsg(model.BotActionResponse{
			Version: "1",
			Type:    "action_resp",
			Action:  "ban",
			Success: rec != nil,
			Message: fmt.Sprintf("IP %s banned until %s", resp.IP, rec.ExpiresAt.Format("2006-01-02 15:04:05")),
		})

	default:
		return fmt.Errorf("Unknown response type: %s", resp.Type)
	}
}

// func (s *Server) handleConnection(conn net.Conn) error {
// 	defer conn.Close()
// 	// 等待hello消息
// 	if err := conn.SetReadDeadline(time.Now().Add(time.Minute * 5)); err != nil {
// 		// 设置5秒超时
// 		// log.Printf("Failed when set read deadline: %v", err)
// 		return err
// 	}
// 	// 创建解码器
// 	decoder := json.NewDecoder(conn)
// 	var res model.BotIPCResponse
// 	// 读取并解码
// 	if err := decoder.Decode(&res); err != nil {
// 		return err
// 	}
// 	// 读取成功, 取消超时
// 	if err := conn.SetReadDeadline(time.Time{}); err != nil {
// 		return err
// 	}
// 	// 判断协议版本
// 	if res.Version != "1" {
// 		return fmt.Errorf("Unknown response version: %v", res.Version)
// 	}
// 	// 判断是否为hello消息
// 	if res.Type != "hello" {
// 		return fmt.Errorf("Bot ipc connection must start with hello message, received: %v", res.Type)
// 	}
// 	// 开始循环处理
// 	for {
// 		// 清空上一次的结果
// 		res.Type = ""
// 		// 读取并解码
// 		if err := decoder.Decode(&res); err != nil {
// 			return err
// 		}
// 		switch res.Type {
// 		case "stop":
// 			return nil
// 		case "approve":
// 			if res.Approval {
// 				// 通过
// 				s.manager.Decide(res.ID, approval.Approved)
// 			} else {
// 				// 拒绝
// 				s.manager.Decide(res.ID, approval.Denied)
// 			}
// 		}
// 	}
// }

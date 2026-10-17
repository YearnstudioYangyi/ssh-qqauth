package botipc

import (
	"fmt"
	"log"
	"net"

	"example.com/qqauth/internal/approval"
	"example.com/qqauth/internal/model"
)

type Server struct {
	socketPath string
	listener   *net.UnixListener
	manager    *approval.Manager
	*connection
}

func NewServer(socketPath string, manager *approval.Manager) *Server {
	return &Server{
		socketPath: socketPath,
		manager:    manager,
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
		}
		con := newConnection(conn)
		if err := con.Serve(s.handleResponse); err != nil {
			log.Printf("Bot IPC connection exit: %v", err)
		}
	}
}

// 发送一个请求
func (s *Server) Send(req approval.Request) error {
	return s.connection.Send(model.BotIPCRequest{
		ID:         req.ID,
		Version:    "1",
		Service:    req.Service,
		User:       req.User,
		RemoteHost: req.RemoteHost,
	})
}

func (s *Server) handleResponse(resp model.BotIPCResponse) error {
	if resp.Type != "approve" {
		return fmt.Errorf("Unknown response type")
	}
	// 判断批准还是拒绝
	if resp.Approval {
		return s.manager.Decide(resp.ID, approval.Approved)
	} else {
		return s.manager.Decide(resp.ID, approval.Denied)
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

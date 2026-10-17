package botipc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"example.com/qqauth/internal/model"
)

type handleResponseFunc func(model.BotIPCResponse) error

type connection struct {
	conn   net.Conn
	sendCh chan model.BotIPCRequest
	ctx    context.Context
	cancel context.CancelFunc
}

// 创建一个新的连接
func newConnection(conn net.Conn) *connection {
	ctx, cancel := context.WithCancel(context.Background())
	return &connection{
		conn:   conn,
		sendCh: make(chan model.BotIPCRequest),
		cancel: cancel,
		ctx:    ctx,
	}
}

// 发送批准请求
func (conn *connection) Send(req model.BotIPCRequest) error {
	select {
	case conn.sendCh <- req:
		return nil
	case <-conn.ctx.Done():
		return fmt.Errorf("Try to send data on closed Bot IPC Connection")
	}
	// conn.sendCh <- req
}

// 启动读写goroutine
func (conn *connection) Serve(handle handleResponseFunc) error {
	go conn.write()
	err := conn.read(handle)
	// 以下函数均为幂等, 多次调用不会报错
	conn.cancel()
	conn.conn.Close()

	return err
}

// Write循环
func (conn *connection) write() {
	encoder := json.NewEncoder(conn.conn)
	for {
		select {
		case <-conn.ctx.Done():
			return
		case req := <-conn.sendCh:
			if err := encoder.Encode(req); err != nil {
				conn.cancel()
				// 关闭net.Conn, 让read退出
				conn.conn.Close()
				return
			}
		}
	}
}

// Read循环
func (conn *connection) read(handle handleResponseFunc) error {
	decoder := json.NewDecoder(conn.conn)
	for {
		var resp model.BotIPCResponse
		if err := decoder.Decode(&resp); err != nil {
			return err
		}
		if err := handle(resp); err != nil {
			log.Printf("Failed when handle bot ipc response %v beacause %v", resp.ID, err)
		}
	}
}

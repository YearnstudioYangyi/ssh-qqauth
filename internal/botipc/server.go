package botipc

import "net"

type Server struct {
	socketPath string
	listener   *net.UnixListener
}

func NewServer(socketPath string) *Server {
	return &Server{
		socketPath: socketPath,
	}
}

func (s *Server)
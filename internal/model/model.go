package model

// 发送给机器人框架的请求参数
type BotIPCRequest struct {
	Version    string `json:"version"`
	User       string `json:"user"`
	Service    string `json:"service"`
	RemoteHost string `json:"remote_host"`
	ID         string `json:"id"`
}

type BotIPCResponse struct {
	// 协议版本
	Version string `json:"version"`
	// 消息类型
	Type string `json:"type"`
	// 批准的请求ID
	ID string `json:"id"`
	// 是否批准
	Approval bool `json:"approval"`
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

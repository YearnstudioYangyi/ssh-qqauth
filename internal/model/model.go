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
	// 消息类型: approve | ban_list | unban | ban
	Type string `json:"type"`
	// 批准的请求ID
	ID string `json:"id,omitempty"`
	// 是否批准
	Approval bool `json:"approval,omitempty"`
	// 目标IP（用于 unban / ban）
	IP string `json:"ip,omitempty"`
	// 封禁原因
	Reason string `json:"reason,omitempty"`
}

type Req struct {
	Version    uint   `json:"version"`
	Type       string `json:"type"`
	Service    string `json:"service"`
	User       string `json:"user"`
	RemoteHost string `json:"remote_host"`
	PIN        string `json:"pin"`
}

type Resp struct {
	Version  uint   `json:"version"`
	Type     string `json:"type"`
	Approved bool   `json:"approved"`
	Message  string `json:"message,omitempty"`
}

type AuthRequestInfo struct {
	Version uint   `json:"version"`
	Type    string `json:"type"`
	ID      string `json:"id"`
}

// 发送给 Bot 的安全告警消息
type BotAlertMessage struct {
	Version   string `json:"version"`
	Type      string `json:"type"`       // "alert"
	AlertType string `json:"alert_type"` // "user_not_found" | "denied_ban" | "rate_limit_ban" | "invalid_pin_ban"
	IP        string `json:"ip"`
	User      string `json:"user"`
	Service   string `json:"service"`
	Reason    string `json:"reason"`
}

// 封禁列表项
type BanItem struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	BannedAt  string `json:"banned_at"`
	ExpiresAt string `json:"expires_at"`
}

// 发送给 Bot 的封禁列表
type BotBanListResponse struct {
	Version string    `json:"version"`
	Type    string    `json:"type"` // "ban_list_resp"
	Items   []BanItem `json:"items"`
}

// 发送给 Bot 的操作结果反馈
type BotActionResponse struct {
	Version string `json:"version"`
	Type    string `json:"type"` // "action_resp"
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

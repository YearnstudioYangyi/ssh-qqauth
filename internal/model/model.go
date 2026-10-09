package model

// 发送给机器人框架的请求参数
type ApprovalNotifacation struct {
	User       string `json:"user"`
	Service    string `json:"service"`
	RemoteHost string `json:"remote_host"`
	ID         string `json:"id"`
}

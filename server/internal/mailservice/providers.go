package mailservice

import (
	"strings"

	"github.com/amine123max/Mail/server/internal/model"
)

// Provider 描述一个邮箱提供商的连接参数。
type Provider struct {
	ID       string   // "outlook", "gmail", "qq", "163", "yahoo", "aliyun", "custom"
	Name     string   // 显示名
	IMAPHost string   // IMAP 服务器地址
	IMAPPort int      // IMAP 端口
	IMAPSSL  string   // "tls" (隐式 TLS) | "starttls"
	SMTPHost string   // SMTP 服务器地址
	SMTPPort int      // SMTP 端口
	SMTPSSL  string   // "tls" | "starttls"
	AuthMode string   // "xoauth2" (OAuth 令牌) | "plain" (用户名+密码/授权码)
	Domains  []string // 用于自动识别的邮箱后缀
}

var providerRegistry = []Provider{
	{
		ID: "outlook", Name: "Outlook / Hotmail",
		IMAPHost: "outlook.office365.com", IMAPPort: 993, IMAPSSL: "tls",
		SMTPHost: "smtp-mail.outlook.com", SMTPPort: 587, SMTPSSL: "starttls",
		AuthMode: "xoauth2",
		Domains:  []string{"outlook.com", "hotmail.com", "live.com", "msn.com"},
	},
	{
		ID: "gmail", Name: "Gmail",
		IMAPHost: "imap.gmail.com", IMAPPort: 993, IMAPSSL: "tls",
		SMTPHost: "smtp.gmail.com", SMTPPort: 465, SMTPSSL: "tls",
		AuthMode: "plain",
		Domains:  []string{"gmail.com", "googlemail.com"},
	},
	{
		ID: "qq", Name: "QQ 邮箱",
		IMAPHost: "imap.qq.com", IMAPPort: 993, IMAPSSL: "tls",
		SMTPHost: "smtp.qq.com", SMTPPort: 465, SMTPSSL: "tls",
		AuthMode: "plain",
		Domains:  []string{"qq.com", "foxmail.com"},
	},
	{
		ID: "163", Name: "163 / 126 邮箱",
		IMAPHost: "imap.163.com", IMAPPort: 993, IMAPSSL: "tls",
		SMTPHost: "smtp.163.com", SMTPPort: 465, SMTPSSL: "tls",
		AuthMode: "plain",
		Domains:  []string{"163.com", "126.com", "yeah.net", "netease.com"},
	},
	{
		ID: "yahoo", Name: "Yahoo Mail",
		IMAPHost: "imap.mail.yahoo.com", IMAPPort: 993, IMAPSSL: "tls",
		SMTPHost: "smtp.mail.yahoo.com", SMTPPort: 465, SMTPSSL: "tls",
		AuthMode: "plain",
		Domains:  []string{"yahoo.com", "yahoo.co.jp", "yahoo.co.uk"},
	},
	{
		ID: "aliyun", Name: "阿里邮箱",
		IMAPHost: "imap.aliyun.com", IMAPPort: 993, IMAPSSL: "tls",
		SMTPHost: "smtp.aliyun.com", SMTPPort: 465, SMTPSSL: "tls",
		AuthMode: "plain",
		Domains:  []string{"aliyun.com"},
	},
}

// IdentifyProvider 根据邮箱地址后缀返回 provider ID。
// 未匹配时返回 "custom"。
func IdentifyProvider(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return "custom"
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, p := range providerRegistry {
		for _, d := range p.Domains {
			if domain == d {
				return p.ID
			}
		}
	}
	return "custom"
}

// GetProvider 按 ID 查找预置提供商。
func GetProvider(id string) (Provider, bool) {
	for _, p := range providerRegistry {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// AllProviders 返回全部预置提供商列表（用于前端展示）。
func AllProviders() []Provider {
	out := make([]Provider, len(providerRegistry))
	copy(out, providerRegistry)
	return out
}

// resolveProvider 根据 account 的类型和 provider 字段解析出实际连接参数。
// - outlook 账号：返回 outlook provider，IMAP 主机回退到 cfg.IMAPHosts
// - imap 账号 + 预置 provider：返回注册表中的 provider
// - imap 账号 + custom provider：用 account 中存储的自定义主机构造 provider
func (s *Service) resolveProvider(account *model.AccountCredentials) Provider {
	if account == nil {
		outlook, _ := GetProvider("outlook")
		return outlook
	}
	if account.AccountType == "outlook" || account.AccountType == "" {
		outlook, _ := GetProvider("outlook")
		// 如果配置了自定义 Outlook IMAP 主机，则覆盖
		if len(s.cfg.IMAPHosts) > 0 && s.cfg.IMAPHosts[0] != outlook.IMAPHost {
			outlook.IMAPHost = s.cfg.IMAPHosts[0]
		}
		if len(s.cfg.SMTPHosts) > 0 && s.cfg.SMTPHosts[0] != outlook.SMTPHost {
			outlook.SMTPHost = s.cfg.SMTPHosts[0]
		}
		return outlook
	}
	// 标准 IMAP 账号
	if account.Provider != "" && account.Provider != "custom" {
		if p, ok := GetProvider(account.Provider); ok {
			return p
		}
	}
	// 自定义 IMAP：用账号中存储的主机信息构造
	port := account.IMAPPort
	if port == 0 {
		port = 993
	}
	smtpPort := account.SMTPPort
	if smtpPort == 0 {
		smtpPort = 465
	}
	return Provider{
		ID:       "custom",
		Name:     "自定义 IMAP",
		IMAPHost: account.IMAPHost,
		IMAPPort: port,
		IMAPSSL:  "tls",
		SMTPHost: account.SMTPHost,
		SMTPPort: smtpPort,
		SMTPSSL:  "tls",
		AuthMode: "plain",
	}
}

// isIMAPAccount 判断账号是否为标准 IMAP 类型（非 OAuth）。
func isIMAPAccount(account *model.AccountCredentials) bool {
	return account != nil && account.AccountType == "imap"
}
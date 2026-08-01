package mailservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"time"

	"github.com/amine123max/Mail/server/internal/model"
)

type smtpEndpoint struct {
	Address    string
	ServerName string
	TLSConfig  *tls.Config
}

type xoauth2SMTPAuth struct {
	username string
	token    string
}

func (auth *xoauth2SMTPAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("XOAUTH2 requires an encrypted SMTP connection")
	}
	payload := "user=" + auth.username + "\x01auth=Bearer " + auth.token + "\x01\x01"
	return "XOAUTH2", []byte(payload), nil
}

func (auth *xoauth2SMTPAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(challenge)); err == nil && len(decoded) > 0 {
		return nil, fmt.Errorf("SMTP OAuth2 authentication rejected: %s", decoded)
	}
	return nil, errors.New("SMTP OAuth2 authentication rejected")
}

func (s *Service) smtpSend(ctx context.Context, account *model.AccountCredentials, accessToken string, message SendRequest) (SendResult, error) {
	raw, accepted, messageID, err := buildMIMEMessage(account.Email, message)
	if err != nil {
		return SendResult{}, err
	}
	// 标准 IMAP 账号：用户名 + 密码/授权码 SMTP 认证
	if isIMAPAccount(account) {
		return s.smtpSendPlain(ctx, account, raw, accepted, messageID)
	}
	// Outlook OAuth 账号：XOAUTH2 SMTP 认证
	var lastError error
	for _, host := range s.cfg.SMTPHosts {
		endpoint := smtpEndpoint{
			Address:    net.JoinHostPort(host, "587"),
			ServerName: host,
			TLSConfig:  &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		}
		if result, err := sendSMTPXOAUTH2(ctx, endpoint, account.Email, accessToken, accepted, raw, messageID); err == nil {
			result.Transport = "smtp"
			return result, nil
		} else {
			lastError = err
		}
	}
	return SendResult{}, serviceError("SMTP 发件失败："+errorMessage(lastError), "SMTP_SEND_FAILED", http.StatusBadGateway)
}

func sendSMTPXOAUTH2(ctx context.Context, endpoint smtpEndpoint, from, accessToken string, recipients []string, raw []byte, messageID string) (SendResult, error) {
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return SendResult{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(45 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return SendResult{}, err
	}
	client, err := smtp.NewClient(connection, endpoint.ServerName)
	if err != nil {
		return SendResult{}, err
	}
	defer client.Close()
	if err := client.Hello("mail.local"); err != nil {
		return SendResult{}, err
	}
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return SendResult{}, errors.New("SMTP server does not support STARTTLS")
	}
	tlsConfig := endpoint.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{ServerName: endpoint.ServerName, MinVersion: tls.VersionTLS12}
	}
	if err := client.StartTLS(tlsConfig.Clone()); err != nil {
		return SendResult{}, err
	}
	if ok, mechanisms := client.Extension("AUTH"); !ok || !containsSMTPMechanism(mechanisms, "XOAUTH2") {
		return SendResult{}, errors.New("SMTP server does not advertise XOAUTH2")
	}
	if err := client.Auth(&xoauth2SMTPAuth{username: from, token: accessToken}); err != nil {
		return SendResult{}, err
	}
	if err := client.Mail(from); err != nil {
		return SendResult{}, err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return SendResult{}, err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return SendResult{}, err
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return SendResult{}, err
	}
	if err := writer.Close(); err != nil {
		return SendResult{}, err
	}
	if err := client.Quit(); err != nil {
		return SendResult{}, err
	}
	return SendResult{MessageID: messageID, Accepted: recipients}, nil
}

func containsSMTPMechanism(value, target string) bool {
	for _, mechanism := range fieldsUpper(value) {
		if mechanism == target {
			return true
		}
	}
	return false
}

func fieldsUpper(value string) []string {
	fields := make([]string, 0)
	current := make([]rune, 0, len(value))
	flush := func() {
		if len(current) > 0 {
			for index, character := range current {
				if character >= 'a' && character <= 'z' {
					current[index] = character - ('a' - 'A')
				}
			}
			fields = append(fields, string(current))
			current = current[:0]
		}
	}
	for _, character := range value {
		if character == ' ' || character == '\t' || character == ',' {
			flush()
			continue
		}
		current = append(current, character)
	}
	flush()
	return fields
}

// smtpSendPlain 用用户名 + 密码/授权码通过标准 SMTP 发件。
func (s *Service) smtpSendPlain(ctx context.Context, account *model.AccountCredentials, raw []byte, recipients []string, messageID string) (SendResult, error) {
	provider := s.resolveProvider(account)
	host := provider.SMTPHost
	port := provider.SMTPPort
	if port == 0 {
		port = 465
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: 20 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return SendResult{}, serviceError("SMTP 连接失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}
	defer connection.Close()

	deadline := time.Now().Add(45 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return SendResult{}, err
	}

	// 隐式 TLS (端口 465)：直接 TLS 连接
	if provider.SMTPSSL == "tls" {
		tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		tlsConn := tls.Client(connection, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return SendResult{}, serviceError("SMTP TLS 握手失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
		}
		connection = tlsConn
	}

	smtpClient, err := smtp.NewClient(connection, host)
	if err != nil {
		return SendResult{}, serviceError("SMTP 客户端初始化失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}
	defer smtpClient.Close()

	if err := smtpClient.Hello("mail.local"); err != nil {
		return SendResult{}, serviceError("SMTP HELO 失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}

	// STARTTLS (端口 587)：先明文连接再升级
	if provider.SMTPSSL == "starttls" {
		if ok, _ := smtpClient.Extension("STARTTLS"); !ok {
			return SendResult{}, serviceError("SMTP 服务器不支持 STARTTLS", "SMTP_SEND_FAILED", http.StatusBadGateway)
		}
		if err := smtpClient.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return SendResult{}, serviceError("SMTP STARTTLS 失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
		}
	}

	// PLAIN 认证
	auth := smtp.PlainAuth("", account.Email, account.Password, host)
	if err := smtpClient.Auth(auth); err != nil {
		return SendResult{}, serviceError("SMTP 认证失败：邮箱或授权码不正确", "MAIL_AUTH_REQUIRED", http.StatusUnauthorized)
	}

	if err := smtpClient.Mail(account.Email); err != nil {
		return SendResult{}, serviceError("SMTP 发件人设置失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}
	for _, recipient := range recipients {
		if err := smtpClient.Rcpt(recipient); err != nil {
			return SendResult{}, serviceError("SMTP 收件人设置失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
		}
	}
	writer, err := smtpClient.Data()
	if err != nil {
		return SendResult{}, serviceError("SMTP DATA 失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return SendResult{}, serviceError("SMTP 写入邮件失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}
	if err := writer.Close(); err != nil {
		return SendResult{}, serviceError("SMTP 发送完成失败："+errorMessage(err), "SMTP_SEND_FAILED", http.StatusBadGateway)
	}
	_ = smtpClient.Quit()
	return SendResult{MessageID: messageID, Accepted: recipients, Transport: "smtp"}, nil
}

package importer

import (
	"net/mail"
	"strconv"
	"strings"

	"github.com/amine123max/Mail/server/internal/model"
)

type ParseError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type Result struct {
	Accounts []model.ImportedAccount
	Errors   []ParseError
}

func Parse(raw string) Result {
	result := Result{Accounts: make([]model.ImportedAccount, 0), Errors: make([]ParseError, 0)}
	raw = strings.TrimPrefix(raw, "\ufeff")
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for index, original := range lines {
		lineNumber := index + 1
		line := strings.TrimSpace(original)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		separator := "----"
		parts := strings.Split(line, separator)
		if strings.Contains(line, "\t") {
			separator = "\t"
			parts = strings.FieldsFunc(line, func(character rune) bool { return character == '\t' })
		}
		// 统一 TrimSpace 所有字段
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		email := parts[0]
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
			result.Errors = append(result.Errors, ParseError{Line: lineNumber, Message: "邮箱地址格式无效"})
			continue
		}

		account, parseErr := parseLine(lineNumber, email, parts, separator)
		if parseErr != nil {
			result.Errors = append(result.Errors, *parseErr)
			continue
		}
		result.Accounts = append(result.Accounts, account)
	}
	return result
}

// parseLine 根据字段数量和内容自动识别账号类型。
//
// 格式：
//   4 字段: 邮箱----密码----ClientID----RefreshToken           → outlook
//   2 字段: 邮箱----授权码                                      → imap (自动识别 provider)
//   4 字段: 邮箱----授权码----imap_host----imap_port           → imap (custom)
//   6 字段: 邮箱----授权码----imap_host----imap_port----smtp_host----smtp_port → imap (custom)
func parseLine(lineNumber int, email string, parts []string, separator string) (model.ImportedAccount, *ParseError) {
	switch len(parts) {
	case 2:
		// 邮箱----授权码
		password := parts[1]
		if password == "" {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "授权码不能为空"}
		}
		provider := identifyProvider(email)
		return model.ImportedAccount{
			Email:       email,
			Password:    password,
			AccountType: "imap",
			Provider:    provider,
		}, nil

	case 4:
		// 两种可能：
		//   邮箱----密码----ClientID----RefreshToken  (outlook)
		//   邮箱----授权码----imap_host----imap_port  (custom IMAP)
		field2 := parts[2]
		field3 := parts[3]
		isOutlook := isLikelyClientID(field2)
		if isOutlook {
			password := parts[1]
			clientID := field2
			refreshToken := strings.Join(parts[3:], separator)
			if password == "" || clientID == "" || refreshToken == "" {
				return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "四个字段都不能为空"}
			}
			return model.ImportedAccount{
				Email:        email,
				Password:     password,
				ClientID:     clientID,
				RefreshToken: refreshToken,
				AccountType:  "outlook",
			}, nil
		}
		// custom IMAP: 邮箱----授权码----imap_host----imap_port
		password := parts[1]
		imapHost := field2
		imapPort, portErr := strconv.Atoi(field3)
		if portErr != nil || imapPort < 1 || imapPort > 65535 {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "IMAP 端口必须是 1-65535 的整数"}
		}
		if password == "" || imapHost == "" {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "授权码和 IMAP 主机不能为空"}
		}
		return model.ImportedAccount{
			Email:       email,
			Password:    password,
			AccountType: "imap",
			Provider:    "custom",
			IMAPHost:    imapHost,
			IMAPPort:    imapPort,
		}, nil

	case 6:
		// 邮箱----授权码----imap_host----imap_port----smtp_host----smtp_port
		password := parts[1]
		imapHost := parts[2]
		imapPort, portErr := strconv.Atoi(parts[3])
		if portErr != nil || imapPort < 1 || imapPort > 65535 {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "IMAP 端口必须是 1-65535 的整数"}
		}
		smtpHost := parts[4]
		smtpPort, smtpPortErr := strconv.Atoi(parts[5])
		if smtpPortErr != nil || smtpPort < 1 || smtpPort > 65535 {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "SMTP 端口必须是 1-65535 的整数"}
		}
		if password == "" || imapHost == "" || smtpHost == "" {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "授权码、IMAP/SMTP 主机不能为空"}
		}
		return model.ImportedAccount{
			Email:       email,
			Password:    password,
			AccountType: "imap",
			Provider:    "custom",
			IMAPHost:    imapHost,
			IMAPPort:    imapPort,
			SMTPHost:    smtpHost,
			SMTPPort:    smtpPort,
		}, nil

	default:
		if len(parts) < 2 {
			return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "至少需要邮箱和密码/授权码两个字段"}
		}
		if len(parts) > 4 {
			// outlook 格式：第 3 字段是 ClientID，第 4+ 字段合并为 RefreshToken
			password := parts[1]
			clientID := parts[2]
			refreshToken := strings.Join(parts[3:], separator)
			if password == "" || clientID == "" || refreshToken == "" {
				return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "四个字段都不能为空"}
			}
			return model.ImportedAccount{
				Email:        email,
				Password:     password,
				ClientID:     clientID,
				RefreshToken: refreshToken,
				AccountType:  "outlook",
			}, nil
		}
		return model.ImportedAccount{}, &ParseError{Line: lineNumber, Message: "无法识别的格式：支持 2 字段（邮箱+授权码）、4 字段（Outlook 或自定义IMAP）、6 字段（完整自定义IMAP+SMTP）"}
	}
}

// isLikelyClientID 判断字段是否像微软 Client ID（UUID 格式）而非 IMAP 主机名。
func isLikelyClientID(value string) bool {
	// 微软 Client ID 是 UUID 格式：8-4-4-4-12
	if len(value) == 36 {
		dashes := 0
		for i, c := range value {
			if c == '-' {
				dashes++
				continue
			}
			_ = i
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return dashes == 4
	}
	// 如果包含点号且没有空格，更像主机名 → 不是 ClientID
	if strings.Contains(value, ".") && !strings.ContainsAny(value, " ") {
		return false
	}
	// 如果不含点号且长度 >= 8，可能是 ClientID
	return len(value) >= 8 && !strings.Contains(value, ".")
}

// identifyProvider 根据邮箱后缀返回 provider ID。
func identifyProvider(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return "custom"
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	switch domain {
	case "gmail.com", "googlemail.com":
		return "gmail"
	case "qq.com", "foxmail.com":
		return "qq"
	case "163.com", "126.com", "yeah.net", "netease.com":
		return "163"
	case "yahoo.com", "yahoo.co.jp", "yahoo.co.uk":
		return "yahoo"
	case "aliyun.com":
		return "aliyun"
	default:
		return "custom"
	}
}

func Serialize(accounts []model.AccountCredentials) string {
	lines := make([]string, len(accounts))
	for index, account := range accounts {
		if account.AccountType == "imap" {
			if account.Provider == "custom" && account.IMAPHost != "" {
				if account.SMTPHost != "" {
					lines[index] = strings.Join([]string{
						account.Email, account.Password,
						account.IMAPHost, strconv.Itoa(account.IMAPPort),
						account.SMTPHost, strconv.Itoa(account.SMTPPort),
					}, "----")
				} else {
					lines[index] = strings.Join([]string{
						account.Email, account.Password,
						account.IMAPHost, strconv.Itoa(account.IMAPPort),
					}, "----")
				}
			} else {
				lines[index] = strings.Join([]string{account.Email, account.Password}, "----")
			}
		} else {
			lines[index] = strings.Join([]string{account.Email, account.Password, account.ClientID, account.RefreshToken}, "----")
		}
	}
	return strings.Join(lines, "\n")
}
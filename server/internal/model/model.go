package model

import "github.com/amine123max/Mail/server/internal/desktopcontract"

type StoredAccount struct {
	ID                    int64
	OwnerKey              string
	EmailEncrypted        string
	EmailHash             string
	PasswordEncrypted     string
	ClientIDEncrypted     string
	RefreshTokenEncrypted string
	Remark                string
	GroupName             string
	SortOrder             int
	CreatedAt             string
	UpdatedAt             string
	LastSyncAt            *string
	AccountType           string
	Provider              string
	IMAPHost              string
	IMAPPort              int
	SMTPHost              string
	SMTPPort              int
}

type AccountCredentials struct {
	ID           int64  `json:"id"`
	OwnerKey     string `json:"-"`
	Email        string `json:"email"`
	Password     string `json:"-"`
	ClientID     string `json:"-"`
	RefreshToken string `json:"-"`
	Remark       string `json:"remark"`
	AccountType  string `json:"accountType"`
	Provider     string `json:"provider"`
	IMAPHost     string `json:"-"`
	IMAPPort     int    `json:"-"`
	SMTPHost     string `json:"-"`
	SMTPPort     int    `json:"-"`
}

type ImportedAccount struct {
	Email        string
	Password     string
	ClientID     string
	RefreshToken string
	Remark       string
	AccountType  string
	Provider     string
	IMAPHost     string
	IMAPPort     int
	SMTPHost     string
	SMTPPort     int
}

type PublicAccount struct {
	ID          int64   `json:"id"`
	Email       string  `json:"email"`
	Remark      string  `json:"remark"`
	Group       string  `json:"group"`
	AccountType string  `json:"accountType"`
	Provider    string  `json:"provider"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
	LastSyncAt  *string `json:"lastSyncAt"`
}

type User struct {
	ID             int64
	Username       string
	EmailEncrypted *string
	EmailHash      *string
	PasswordHash   string
	IsAdmin        bool
	DisabledAt     *string
	CreatedAt      string
}

type AdminUserSummary struct {
	ID            int64   `json:"id"`
	Username      string  `json:"username"`
	Email         string  `json:"email"`
	Administrator bool    `json:"administrator"`
	Disabled      bool    `json:"disabled"`
	DisabledAt    *string `json:"disabledAt"`
	AccountCount  int     `json:"accountCount"`
	CreatedAt     string  `json:"createdAt"`
}

type Announcement struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Author    string `json:"author"`
	CreatedAt string `json:"createdAt"`
	Read      bool   `json:"read"`
}

type APIKey struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	CreatedAt  string  `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt"`
}

type CreatedAPIKey struct {
	APIKey
	Token string `json:"token"`
}

type Identity struct {
	Kind     string
	OwnerKey string
	UserID   int64
	Username string
	IsAdmin  bool
	GuestID  string
}

type DesktopSession struct {
	ID                string
	FamilyID          string
	DeviceID          string
	UserID            int64
	DeviceName        string
	ClientVersion     string
	CreatedAt         string
	LastUsedAt        string
	IdleExpiresAt     string
	AbsoluteExpiresAt string
	RevokedAt         *string
	RevokeReason      *string
}

type DesktopDeviceSummary = desktopcontract.DesktopDeviceSummary

package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/amine123max/Mail/server/internal/auth"
	"github.com/amine123max/Mail/server/internal/mailservice"
	"github.com/amine123max/Mail/server/internal/model"
	"github.com/amine123max/Mail/server/internal/store"
)

var scriptPlatformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (s *Server) scriptAPICapabilities(response http.ResponseWriter, _ *http.Request) error {
	writeJSON(response, http.StatusOK, map[string]any{
		"version": 1,
		"scopes":  []string{"inbox.lease", "mail.read"},
	})
	return nil
}

func (s *Server) leaseScriptInbox(response http.ResponseWriter, request *http.Request) error {
	var body struct {
		Group    string `json:"group"`
		Platform string `json:"platform"`
	}
	if err := decodeJSON(response, request, &body); err != nil {
		return err
	}
	group := strings.TrimSpace(body.Group)
	platform := strings.ToLower(strings.TrimSpace(body.Platform))
	if n := utf8.RuneCountInString(group); n < 1 || n > 64 {
		return validation("分组名称必须为 1-64 个字符")
	}
	if !scriptPlatformPattern.MatchString(platform) {
		return validation("platform 必须为 1-64 位小写字母、数字、连字符或下划线")
	}
	occupancy, err := s.store.LeaseInbox(request.Context(), identityFrom(request).UserID, apiKeyIDFrom(request), group, platform)
	if errors.Is(err, store.ErrInboxPoolExhausted) {
		return &auth.Error{Message: "该分组没有可租用的邮箱", Code: "INBOX_POOL_EXHAUSTED", Status: http.StatusConflict}
	}
	if err != nil {
		return err
	}
	writeJSON(response, http.StatusCreated, scriptLeaseJSON(occupancy))
	return nil
}

func (s *Server) completeScriptInboxLease(response http.ResponseWriter, request *http.Request) error {
	occupancy, err := s.store.CompleteInboxLease(request.Context(), apiKeyIDFrom(request), request.PathValue("leaseId"))
	return s.writeScriptLeaseMutation(response, occupancy, err)
}

func (s *Server) releaseScriptInboxLease(response http.ResponseWriter, request *http.Request) error {
	if request.Body != nil && request.ContentLength != 0 {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeJSON(response, request, &body); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	occupancy, err := s.store.ReleaseInboxLease(request.Context(), apiKeyIDFrom(request), request.PathValue("leaseId"))
	return s.writeScriptLeaseMutation(response, occupancy, err)
}

func (s *Server) writeScriptLeaseMutation(response http.ResponseWriter, occupancy *model.InboxOccupancy, err error) error {
	if errors.Is(err, store.ErrInboxLeaseNotFound) {
		return &auth.Error{Message: "租约不存在或已结束", Code: "INBOX_LEASE_NOT_FOUND", Status: http.StatusNotFound}
	}
	if err != nil {
		return err
	}
	writeJSON(response, http.StatusOK, scriptLeaseJSON(occupancy))
	return nil
}

func (s *Server) listScriptInboxMessages(response http.ResponseWriter, request *http.Request) error {
	account, err := s.scriptLeaseAccount(request)
	if err != nil {
		return err
	}
	result, err := s.mail.ListMessages(request.Context(), account, "INBOX", 1, 100, "")
	if err != nil {
		return err
	}
	writeJSON(response, http.StatusOK, map[string]any{"messages": scriptMessageSummaries(result)})
	return nil
}

func (s *Server) getScriptInboxMessage(response http.ResponseWriter, request *http.Request) error {
	account, err := s.scriptLeaseAccount(request)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(request.PathValue("id"))
	if id == "" || len(id) > 1000 {
		return validation("邮件编号不正确")
	}
	detail, err := s.mail.GetMessage(request.Context(), account, "INBOX", id)
	if err != nil {
		return err
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"id":         fmt.Sprint(detail.UID),
		"from":       detail.From,
		"subject":    detail.Subject,
		"receivedAt": detail.Date,
		"text":       detail.Text,
		"html":       detail.HTML,
	})
	return nil
}

func (s *Server) scriptLeaseAccount(request *http.Request) (*model.AccountCredentials, error) {
	occupancy, err := s.store.ActiveInboxLease(request.Context(), apiKeyIDFrom(request), request.PathValue("leaseId"))
	if errors.Is(err, store.ErrInboxLeaseNotFound) {
		return nil, &auth.Error{Message: "租约不存在或已结束", Code: "INBOX_LEASE_NOT_FOUND", Status: http.StatusNotFound}
	}
	if err != nil {
		return nil, err
	}
	account, err := s.store.GetAccountCredentials(request.Context(), identityFrom(request).OwnerKey, occupancy.AccountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, &mailservice.Error{Message: "邮箱账号不存在", Code: "ACCOUNT_NOT_FOUND", Status: http.StatusNotFound}
	}
	return account, nil
}

func scriptLeaseJSON(occupancy *model.InboxOccupancy) map[string]any {
	payload := map[string]any{
		"leaseId":  occupancy.LeaseID,
		"email":    occupancy.Email,
		"platform": occupancy.Platform,
		"group":    occupancy.GroupName,
		"status":   occupancy.Status,
	}
	if occupancy.ExpiresAt != nil {
		payload["expiresAt"] = occupancy.ExpiresAt
	}
	return payload
}

func scriptMessageSummaries(result map[string]any) []map[string]any {
	messages := make([]map[string]any, 0)
	switch items := result["messages"].(type) {
	case []mailservice.MessageSummary:
		for _, item := range items {
			messages = append(messages, map[string]any{
				"id":         fmt.Sprint(item.UID),
				"from":       item.From,
				"subject":    item.Subject,
				"receivedAt": item.Date,
			})
		}
	}
	return messages
}

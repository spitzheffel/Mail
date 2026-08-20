package httpapi

import (
	"net/http"
	"strings"

	"github.com/amine123max/Mail/server/internal/model"
)

func (s *Server) listAPIKeys(response http.ResponseWriter, request *http.Request) error {
	keys, err := s.auth.ListAPIKeys(request.Context(), identityFrom(request).UserID)
	if err != nil {
		return err
	}
	if keys == nil {
		keys = []model.APIKey{}
	}
	writeJSON(response, http.StatusOK, map[string]any{"keys": keys})
	return nil
}

func (s *Server) createAPIKey(response http.ResponseWriter, request *http.Request) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(response, request, &body); err != nil {
		return err
	}
	created, err := s.auth.CreateAPIKey(request.Context(), identityFrom(request).UserID, strings.TrimSpace(body.Name))
	if err != nil {
		return err
	}
	writeJSON(response, http.StatusCreated, created)
	return nil
}

func (s *Server) deleteAPIKey(response http.ResponseWriter, request *http.Request) error {
	id, err := parseID(request.PathValue("id"))
	if err != nil {
		return validation("API Key 编号不正确")
	}
	if err := s.auth.DeleteAPIKey(request.Context(), identityFrom(request).UserID, id); err != nil {
		return err
	}
	response.WriteHeader(http.StatusNoContent)
	return nil
}

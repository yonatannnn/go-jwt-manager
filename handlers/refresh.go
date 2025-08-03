package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/yonatannnn/go-jwt-manager/auth"
)

type RefreshHandler struct {
	AccessManager  *auth.JWTManager
	RefreshManager *auth.RefreshManager
}

func NewRefreshHandler(access *auth.JWTManager, refresh *auth.RefreshManager) *RefreshHandler {
	return &RefreshHandler{
		AccessManager:  access,
		RefreshManager: refresh,
	}
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken string `json:"access_token"`
}

func (h *RefreshHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	claims, err := h.RefreshManager.Verify(req.RefreshToken)
	if err != nil {
		http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Re-issue access token from claims
	newAccessToken, err := h.AccessManager.Generate(claims)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(RefreshResponse{
		AccessToken: newAccessToken,
	})
}

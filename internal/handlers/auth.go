package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"mokos_lockdoor/internal/ttlock"
)

type tokenRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	MD5      bool   `json:"md5,omitempty"` // if true, password already MD5 hashed
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	UID          int64  `json:"uid"`
	ExpiresAt    int64  `json:"expires_at"`
}

type verifyAccountResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

func NewAuthHandler(client *ttlock.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body tokenRequest
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, expAt, err := client.AuthenticatePassword(c.Request.Context(), body.Username, body.Password, body.MD5)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, tokenResponse{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    token.ExpiresIn,
			UID:          token.UID,
			ExpiresAt:    expAt.UnixMilli(),
		})
	}
}

func NewVerifyAccountHandler(client *ttlock.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body tokenRequest
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if _, _, err := client.AuthenticatePassword(c.Request.Context(), body.Username, body.Password, body.MD5); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, verifyAccountResponse{
			Verified: true,
			Message:  "ttlock account verified",
		})
	}
}

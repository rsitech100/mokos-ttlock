package handlers

import (
	"mokos_lockdoor/internal/hashutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

type md5Request struct {
	Password string `json:"password" binding:"required"`
}

type md5Response struct {
	Hash string `json:"hash"`
}

// NewMD5HashHandler returns a Gin handler that creates an MD5 hash of the supplied password.
func NewMD5HashHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body md5Request
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, md5Response{Hash: hashutil.MD5Hex(body.Password)})
	}
}

package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"mokos_lockdoor/internal/ttlock"
)

type PasscodeHandler struct {
	service *ttlock.Service
}

func NewPasscodeHandler(service *ttlock.Service) gin.HandlerFunc {
	h := &PasscodeHandler{service: service}
	return h.handle
}

func NewReplacePasscodeHandler(service *ttlock.Service) gin.HandlerFunc {
	h := &PasscodeHandler{service: service}
	return h.replace
}

func NewDeletePasscodeHandler(service *ttlock.Service) gin.HandlerFunc {
	h := &PasscodeHandler{service: service}
	return h.delete
}

type passcodeRequestBody struct {
	KostID     string `json:"kost_id" binding:"required"`
	LockID     string `json:"lock_id" binding:"required"`
	Passcode   string `json:"passcode" binding:"required"`
	PasscodeID string `json:"passcode_id,omitempty"`
	CardNumber string `json:"card_number,omitempty"`
	Name       string `json:"name"`
	StartAt    string `json:"start_at" binding:"required"`
	EndAt      string `json:"end_at" binding:"required"`
}

type passcodeResponseBody struct {
	PasscodeID int64  `json:"passcode_id"`
	Passcode   string `json:"passcode"`
	StartAt    int64  `json:"start_at"`
	EndAt      int64  `json:"end_at"`
}

func (h *PasscodeHandler) handle(c *gin.Context) {
	var body passcodeRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req, err := mapRequest(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.GeneratePasscode(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, passcodeResponseBody{
		PasscodeID: result.ID,
		Passcode:   result.Passcode,
		StartAt:    result.StartsAt.UnixMilli(),
		EndAt:      result.ExpiresAt.UnixMilli(),
	})
}

func (h *PasscodeHandler) replace(c *gin.Context) {
	var body passcodeRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req, err := mapRequest(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.ReplacePasscode(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, passcodeResponseBody{
		PasscodeID: result.ID,
		Passcode:   result.Passcode,
		StartAt:    result.StartsAt.UnixMilli(),
		EndAt:      result.ExpiresAt.UnixMilli(),
	})
}

func (h *PasscodeHandler) delete(c *gin.Context) {
	kostID := c.Query("kost_id")
	if kostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kost_id query parameter is required"})
		return
	}

	lockID, err := strconv.ParseInt(c.Query("lock_id"), 10, 64)
	if err != nil || lockID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "lock_id query parameter must be a number"})
		return
	}

	passcodeID, err := strconv.ParseInt(c.Query("passcode_id"), 10, 64)
	if err != nil || passcodeID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passcode_id query parameter must be a number"})
		return
	}

	if err := h.service.DeletePasscode(c.Request.Context(), kostID, lockID, passcodeID); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted":     true,
		"kost_id":     kostID,
		"lock_id":     lockID,
		"passcode_id": passcodeID,
	})
}

func mapRequest(body passcodeRequestBody) (ttlock.PasscodeRequest, error) {
	if strings.TrimSpace(body.KostID) == "" {
		return ttlock.PasscodeRequest{}, errors.New("kost_id is required")
	}

	lockID, err := strconv.ParseInt(body.LockID, 10, 64)
	if err != nil {
		return ttlock.PasscodeRequest{}, errors.New("lock_id must be a number")
	}

	startAt, err := time.Parse(time.RFC3339, body.StartAt)
	if err != nil {
		return ttlock.PasscodeRequest{}, errors.New("start_at must be RFC3339, e.g. 2024-12-24T12:00:00Z")
	}

	endAt, err := time.Parse(time.RFC3339, body.EndAt)
	if err != nil {
		return ttlock.PasscodeRequest{}, errors.New("end_at must be RFC3339, e.g. 2024-12-25T12:00:00Z")
	}

	if endAt.Before(startAt) {
		return ttlock.PasscodeRequest{}, errors.New("end_at must be after start_at")
	}

	if body.Name == "" {
		body.Name = "Passcode"
	}

	var passcodeID int64
	if body.PasscodeID != "" {
		passcodeID, err = strconv.ParseInt(body.PasscodeID, 10, 64)
		if err != nil {
			return ttlock.PasscodeRequest{}, errors.New("passcode_id must be a number")
		}
	}

	return ttlock.PasscodeRequest{
		KostID:     strings.TrimSpace(body.KostID),
		LockID:     lockID,
		Passcode:   body.Passcode,
		PasscodeID: passcodeID,
		CardNumber: body.CardNumber,
		Name:       body.Name,
		Start:      startAt,
		End:        endAt,
	}, nil
}

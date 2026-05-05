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

type CardHandler struct {
	service *ttlock.Service
}

func NewReplaceCardHandler(service *ttlock.Service) gin.HandlerFunc {
	h := &CardHandler{service: service}
	return h.replace
}

func NewAddCardHandler(service *ttlock.Service) gin.HandlerFunc {
	h := &CardHandler{service: service}
	return h.add
}

func NewDeleteCardHandler(service *ttlock.Service) gin.HandlerFunc {
	h := &CardHandler{service: service}
	return h.delete
}

type replaceCardRequestBody struct {
	KostID     string `json:"kost_id" binding:"required"`
	LockID     string `json:"lock_id" binding:"required"`
	CardNumber string `json:"card_number" binding:"required"`
	StartAt    string `json:"start_at" binding:"required"`
	EndAt      string `json:"end_at" binding:"required"`
}

type replaceCardResponseBody struct {
	LockID     int64  `json:"lock_id"`
	CardNumber string `json:"card_number"`
	StartAt    int64  `json:"start_at"`
	EndAt      int64  `json:"end_at"`
}

type addCardRequestBody struct {
	LockID     string `json:"lock_id" binding:"required"`
	CardNumber string `json:"card_number" binding:"required"`
	CardName   string `json:"card_name,omitempty"`
	StartAt    string `json:"start_at" binding:"required"`
	EndAt      string `json:"end_at" binding:"required"`
}

type addCardResponseBody struct {
	Created    bool   `json:"created"`
	LockID     int64  `json:"lock_id"`
	CardID     int64  `json:"card_id"`
	CardNumber string `json:"card_number"`
	CardName   string `json:"card_name,omitempty"`
	StartAt    int64  `json:"start_at"`
	EndAt      int64  `json:"end_at"`
}

type deleteCardRequestQuery struct {
	KostID     string `form:"kost_id" binding:"required"`
	LockID     string `form:"lock_id" binding:"required"`
	CardNumber string `form:"card_number" binding:"required"`
}

func (h *CardHandler) replace(c *gin.Context) {
	var body replaceCardRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req, err := mapReplaceCardRequest(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.ReplaceCardPeriod(c.Request.Context(), req); err != nil {
		if ttlock.IsCardNumberNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, ttlock.ErrCardNumberRequired) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, replaceCardResponseBody{
		LockID:     req.LockID,
		CardNumber: req.CardNumber,
		StartAt:    req.Start.UnixMilli(),
		EndAt:      req.End.UnixMilli(),
	})
}

func (h *CardHandler) add(c *gin.Context) {
	var body addCardRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req, err := mapAddCardRequest(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.AddCard(c.Request.Context(), req)
	if err != nil {
		if ttlock.IsCardNumberNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, ttlock.ErrCardNumberRequired) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, addCardResponseBody{
		Created:    true,
		LockID:     result.LockID,
		CardID:     result.CardID,
		CardNumber: req.CardNumber,
		CardName:   req.CardName,
		StartAt:    req.Start.UnixMilli(),
		EndAt:      req.End.UnixMilli(),
	})
}

func (h *CardHandler) delete(c *gin.Context) {
	var query deleteCardRequestQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req, err := mapDeleteCardRequest(query)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.DeleteCard(c.Request.Context(), req)
	if err != nil {
		if ttlock.IsCardNumberNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, ttlock.ErrCardNumberRequired) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted":     true,
		"kost_id":     req.KostID,
		"lock_id":     result.LockID,
		"card_id":     result.CardID,
		"card_number": req.CardNumber,
	})
}

func mapReplaceCardRequest(body replaceCardRequestBody) (ttlock.ReplaceCardRequest, error) {
	kostID := strings.TrimSpace(body.KostID)
	if kostID == "" {
		return ttlock.ReplaceCardRequest{}, errors.New("kost_id is required")
	}

	lockID, err := strconv.ParseInt(body.LockID, 10, 64)
	if err != nil || lockID <= 0 {
		return ttlock.ReplaceCardRequest{}, errors.New("lock_id must be a number")
	}

	cardNumber := strings.TrimSpace(body.CardNumber)
	if cardNumber == "" {
		return ttlock.ReplaceCardRequest{}, errors.New("card_number is required")
	}

	startAt, err := time.Parse(time.RFC3339, body.StartAt)
	if err != nil {
		return ttlock.ReplaceCardRequest{}, errors.New("start_at must be RFC3339, e.g. 2024-12-24T12:00:00Z")
	}

	endAt, err := time.Parse(time.RFC3339, body.EndAt)
	if err != nil {
		return ttlock.ReplaceCardRequest{}, errors.New("end_at must be RFC3339, e.g. 2024-12-25T12:00:00Z")
	}

	if endAt.Before(startAt) {
		return ttlock.ReplaceCardRequest{}, errors.New("end_at must be after start_at")
	}

	return ttlock.ReplaceCardRequest{
		KostID:     kostID,
		LockID:     lockID,
		CardNumber: cardNumber,
		Start:      startAt,
		End:        endAt,
	}, nil
}

func mapAddCardRequest(body addCardRequestBody) (ttlock.AddCardRequest, error) {
	lockID, err := strconv.ParseInt(body.LockID, 10, 64)
	if err != nil || lockID <= 0 {
		return ttlock.AddCardRequest{}, errors.New("lock_id must be a number")
	}

	cardNumber := strings.TrimSpace(body.CardNumber)
	if cardNumber == "" {
		return ttlock.AddCardRequest{}, errors.New("card_number is required")
	}

	startAt, err := time.Parse(time.RFC3339, body.StartAt)
	if err != nil {
		return ttlock.AddCardRequest{}, errors.New("start_at must be RFC3339, e.g. 2024-12-24T12:00:00Z")
	}

	endAt, err := time.Parse(time.RFC3339, body.EndAt)
	if err != nil {
		return ttlock.AddCardRequest{}, errors.New("end_at must be RFC3339, e.g. 2024-12-25T12:00:00Z")
	}

	if endAt.Before(startAt) {
		return ttlock.AddCardRequest{}, errors.New("end_at must be after start_at")
	}

	return ttlock.AddCardRequest{
		LockID:     lockID,
		CardNumber: cardNumber,
		CardName:   strings.TrimSpace(body.CardName),
		Start:      startAt,
		End:        endAt,
	}, nil
}

func mapDeleteCardRequest(query deleteCardRequestQuery) (ttlock.DeleteCardRequest, error) {
	kostID := strings.TrimSpace(query.KostID)
	if kostID == "" {
		return ttlock.DeleteCardRequest{}, errors.New("kost_id is required")
	}

	lockID, err := strconv.ParseInt(query.LockID, 10, 64)
	if err != nil || lockID <= 0 {
		return ttlock.DeleteCardRequest{}, errors.New("lock_id must be a number")
	}

	cardNumber := strings.TrimSpace(query.CardNumber)
	if cardNumber == "" {
		return ttlock.DeleteCardRequest{}, errors.New("card_number is required")
	}

	return ttlock.DeleteCardRequest{
		KostID:     kostID,
		LockID:     lockID,
		CardNumber: cardNumber,
	}, nil
}

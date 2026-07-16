package ttlock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Service struct {
	baseURL      string
	http         *http.Client
	clientID     string
	clientSecret string
	username     string
	passwordMD5  string
	credsRepo    CredentialStore
}

const defaultOperationTimeout = 30 * time.Second
const maxCardValidityDuration = 24 * time.Hour
const tokenExpiryBuffer = 5 * time.Minute

var (
	ErrPasscodeTooSimple  = errors.New("passcode is too simple")
	ErrPasscodeInvalid    = errors.New("passcode is invalid")
	ErrCardNumberRequired = errors.New("card_number is required")
)

func NewService(baseURL string, httpClient *http.Client, clientID, clientSecret, username, passwordMD5 string, credsRepo CredentialStore) *Service {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &Service{
		baseURL:      strings.TrimSpace(baseURL),
		http:         httpClient,
		clientID:     strings.TrimSpace(clientID),
		clientSecret: strings.TrimSpace(clientSecret),
		username:     strings.TrimSpace(username),
		passwordMD5:  strings.TrimSpace(passwordMD5),
		credsRepo:    credsRepo,
	}
}

type PasscodeRequest struct {
	KostID     string
	LockID     int64
	Passcode   string
	PasscodeID int64
	CardNumber string
	Name       string
	Start      time.Time
	End        time.Time
}

type PasscodeResponse struct {
	ID        int64
	Passcode  string
	ExpiresAt time.Time
	StartsAt  time.Time
}

type ReplaceCardRequest struct {
	KostID     string
	LockID     int64
	CardNumber string
	Start      time.Time
	End        time.Time
}

type AddCardRequest struct {
	KostID     string
	LockID     int64
	CardNumber string
	CardName   string
	Start      time.Time
	End        time.Time
}

type AddCardResponse struct {
	CardID int64
	LockID int64
	Start  time.Time
	End    time.Time
}

type ExtendPasscodeRequest struct {
	KostID     string
	LockID     int64
	PasscodeID int64
	Name       string
	Start      time.Time
	End        time.Time
}

type PasscodeDetail struct {
	ID        int64
	Name      string
	Passcode  string
	StartsAt  time.Time
	ExpiresAt time.Time
}

type CardDetail struct {
	CardID     int64
	CardName   string
	CardNumber string
	StartsAt   time.Time
	ExpiresAt  time.Time
}

type DeleteCardRequest struct {
	KostID     string
	LockID     int64
	CardNumber string
}

type DeleteCardResponse struct {
	CardID int64
	LockID int64
}

func (s *Service) getClientAndAccessToken(ctx context.Context, kostID string) (*Client, string, error) {
	if strings.TrimSpace(kostID) == "" {
		return nil, "", errors.New("kost_id is required")
	}
	if s.clientID == "" || s.clientSecret == "" {
		return nil, "", errors.New("TTLOCK_CLIENT_ID and TTLOCK_CLIENT_SECRET are required")
	}

	creds, err := s.credsRepo.GetActiveByKostID(ctx, kostID)
	if err != nil {
		return nil, "", err
	}

	client := NewClient(s.baseURL, s.clientID, s.clientSecret, s.http)

	if creds.AccessToken.Valid && creds.AccessToken.String != "" && creds.TokenExpiresAt.Valid &&
		time.Now().Add(tokenExpiryBuffer).Before(creds.TokenExpiresAt.Time) {
		return client, creds.AccessToken.String, nil
	}

	token, expiresAt, err := client.AuthenticatePassword(ctx, creds.Email, creds.Password, true)
	if err != nil {
		return nil, "", err
	}

	if err := s.credsRepo.SaveToken(ctx, creds.ID, token.AccessToken, expiresAt); err != nil {
		return nil, "", err
	}

	return client, token.AccessToken, nil
}

func (s *Service) GeneratePasscode(ctx context.Context, req PasscodeRequest) (*PasscodeResponse, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if err := validatePasscodeComplexity(req.Passcode); err != nil {
		return nil, err
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, req.KostID)
	if err != nil {
		return nil, err
	}

	params := KeyboardPwdRequest{
		LockID:      req.LockID,
		Name:        req.Name,
		Start:       req.Start,
		End:         req.End,
		CardNumber:  req.CardNumber,
		AccessToken: accessToken,
		KeyboardPwd: req.Passcode,
	}

	var (
		result *keyboardPwdResponse
	)
	if req.PasscodeID > 0 {
		params.KeyboardPwdID = req.PasscodeID
		result, err = client.ChangeKeyboardPassword(ctx, params)
	} else {
		result, err = client.AddKeyboardPassword(ctx, params)
	}
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.CardNumber) != "" {
		if err := client.ChangeCardPeriodByNumber(ctx, req.LockID, req.CardNumber, req.Start, req.End, accessToken); err != nil {
			if !IsCardNumberNotFound(err) {
				return nil, err
			}
		}
	}

	return &PasscodeResponse{
		ID:        result.KeyboardPwdID,
		Passcode:  result.KeyboardPwd,
		ExpiresAt: req.End,
		StartsAt:  req.Start,
	}, nil
}

func (s *Service) ReplacePasscode(ctx context.Context, req PasscodeRequest) (*PasscodeResponse, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if err := validatePasscodeComplexity(req.Passcode); err != nil {
		return nil, err
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, req.KostID)
	if err != nil {
		return nil, err
	}

	if req.PasscodeID > 0 {
		client.DeleteKeyboardPassword(ctx, KeyboardPwdDeleteRequest{
			LockID:        req.LockID,
			KeyboardPwdID: req.PasscodeID,
			AccessToken:   accessToken,
		})
	}

	result, err := client.AddKeyboardPassword(ctx, KeyboardPwdRequest{
		LockID:      req.LockID,
		Name:        req.Name,
		Start:       req.Start,
		End:         req.End,
		CardNumber:  req.CardNumber,
		AccessToken: accessToken,
		KeyboardPwd: req.Passcode,
	})
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.CardNumber) != "" {
		if err := client.ChangeCardPeriodByNumber(ctx, req.LockID, req.CardNumber, req.Start, req.End, accessToken); err != nil {
			if !IsCardNumberNotFound(err) {
				return nil, err
			}
		}
	}

	return &PasscodeResponse{
		ID:        result.KeyboardPwdID,
		Passcode:  result.KeyboardPwd,
		ExpiresAt: req.End,
		StartsAt:  req.Start,
	}, nil
}

func (s *Service) DeletePasscode(ctx context.Context, kostID string, lockID, passcodeID int64) error {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	client, accessToken, err := s.getClientAndAccessToken(ctx, kostID)
	if err != nil {
		return err
	}
	return client.DeleteKeyboardPassword(ctx, KeyboardPwdDeleteRequest{
		LockID:        lockID,
		KeyboardPwdID: passcodeID,
		AccessToken:   accessToken,
	})
}

func (s *Service) ExtendPasscode(ctx context.Context, req ExtendPasscodeRequest) (*PasscodeResponse, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if req.LockID <= 0 {
		return nil, errors.New("lock_id is required")
	}
	if req.PasscodeID <= 0 {
		return nil, errors.New("passcode_id is required")
	}
	if req.End.Before(req.Start) {
		return nil, errors.New("end_at must be after start_at")
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, req.KostID)
	if err != nil {
		return nil, err
	}

	current, err := client.GetKeyboardPasswordByID(ctx, req.LockID, req.PasscodeID, accessToken)
	if err != nil {
		return nil, err
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = current.KeyboardPwdName
	}

	result, err := client.ChangeKeyboardPassword(ctx, KeyboardPwdRequest{
		LockID:        req.LockID,
		KeyboardPwdID: req.PasscodeID,
		Name:          name,
		Start:         req.Start,
		End:           req.End,
		KeyboardPwd:   current.KeyboardPwd,
		AccessToken:   accessToken,
	})
	if err != nil {
		return nil, err
	}

	return &PasscodeResponse{
		ID:        result.KeyboardPwdID,
		Passcode:  result.KeyboardPwd,
		ExpiresAt: req.End,
		StartsAt:  req.Start,
	}, nil
}

func (s *Service) GetPasscode(ctx context.Context, kostID string, lockID, passcodeID int64) (*PasscodeDetail, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if lockID <= 0 {
		return nil, errors.New("lock_id is required")
	}
	if passcodeID <= 0 {
		return nil, errors.New("passcode_id is required")
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, kostID)
	if err != nil {
		return nil, err
	}

	item, err := client.GetKeyboardPasswordByID(ctx, lockID, passcodeID, accessToken)
	if err != nil {
		return nil, err
	}

	return &PasscodeDetail{
		ID:        item.KeyboardPwdID,
		Name:      item.KeyboardPwdName,
		Passcode:  item.KeyboardPwd,
		StartsAt:  time.UnixMilli(item.StartDate),
		ExpiresAt: time.UnixMilli(item.EndDate),
	}, nil
}

func withOperationTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultOperationTimeout)
}

func validatePasscodeComplexity(passcode string) error {
	passcode = strings.TrimSpace(passcode)
	if passcode == "" {
		return errors.New("passcode is required")
	}

	for _, r := range passcode {
		if r < '0' || r > '9' {
			return fmt.Errorf("%w: must contain only digits", ErrPasscodeInvalid)
		}
	}

	if hasRepeatedDigits(passcode) {
		return fmt.Errorf("%w: repeated digits are not allowed", ErrPasscodeTooSimple)
	}
	if hasConsecutiveDigits(passcode) {
		return fmt.Errorf("%w: consecutive digits are not allowed", ErrPasscodeTooSimple)
	}

	return nil
}

func hasRepeatedDigits(passcode string) bool {
	if len(passcode) == 0 {
		return false
	}

	first := passcode[0]
	for i := 1; i < len(passcode); i++ {
		if passcode[i] != first {
			return false
		}
	}
	return true
}

func hasConsecutiveDigits(passcode string) bool {
	if len(passcode) < 2 {
		return false
	}

	ascending := true
	descending := true
	for i := 1; i < len(passcode); i++ {
		prev := int(passcode[i-1] - '0')
		curr := int(passcode[i] - '0')

		if curr-prev != 1 {
			ascending = false
		}
		if prev-curr != 1 {
			descending = false
		}
	}

	return ascending || descending
}

func (s *Service) ReplaceCardPeriod(ctx context.Context, req ReplaceCardRequest) error {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(req.CardNumber) == "" {
		return ErrCardNumberRequired
	}
	if req.LockID <= 0 {
		return errors.New("lock_id is required")
	}
	if req.End.Before(req.Start) {
		return errors.New("end_at must be after start_at")
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, req.KostID)
	if err != nil {
		return err
	}

	return client.ChangeCardPeriodByNumber(ctx, req.LockID, req.CardNumber, req.Start, req.End, accessToken)
}

func (s *Service) AddCard(ctx context.Context, req AddCardRequest) (*AddCardResponse, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(req.CardNumber) == "" {
		return nil, ErrCardNumberRequired
	}
	if req.LockID <= 0 {
		return nil, errors.New("lock_id is required")
	}
	if req.End.Before(req.Start) {
		return nil, errors.New("end_at must be after start_at")
	}

	effectiveEnd := req.End
	maxEnd := req.Start.Add(maxCardValidityDuration)
	if effectiveEnd.After(maxEnd) {
		effectiveEnd = maxEnd
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, req.KostID)
	if err != nil {
		return nil, err
	}

	cardID, err := client.AddCardByNumber(ctx, req.LockID, req.CardNumber, req.CardName, req.Start, effectiveEnd, accessToken)
	if err != nil {
		return nil, err
	}

	return &AddCardResponse{
		CardID: cardID,
		LockID: req.LockID,
		Start:  req.Start,
		End:    effectiveEnd,
	}, nil
}

func (s *Service) GetCard(ctx context.Context, kostID string, lockID int64, cardNumber string) (*CardDetail, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(cardNumber) == "" {
		return nil, ErrCardNumberRequired
	}
	if lockID <= 0 {
		return nil, errors.New("lock_id is required")
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, kostID)
	if err != nil {
		return nil, err
	}

	card, err := client.GetCardByNumber(ctx, lockID, cardNumber, accessToken)
	if err != nil {
		return nil, err
	}

	return &CardDetail{
		CardID:     card.CardID,
		CardName:   card.CardName,
		CardNumber: card.CardNumber,
		StartsAt:   time.UnixMilli(card.StartDate),
		ExpiresAt:  time.UnixMilli(card.EndDate),
	}, nil
}

func (s *Service) DeleteCard(ctx context.Context, req DeleteCardRequest) (*DeleteCardResponse, error) {
	ctx, cancel := withOperationTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(req.CardNumber) == "" {
		return nil, ErrCardNumberRequired
	}
	if req.LockID <= 0 {
		return nil, errors.New("lock_id is required")
	}

	client, accessToken, err := s.getClientAndAccessToken(ctx, req.KostID)
	if err != nil {
		return nil, err
	}

	cardID, err := client.DeleteCardByNumber(ctx, req.LockID, req.CardNumber, accessToken)
	if err != nil {
		return nil, err
	}

	return &DeleteCardResponse{CardID: cardID, LockID: req.LockID}, nil
}

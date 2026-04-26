package ttlock

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type Service struct {
	baseURL      string
	http         *http.Client
	clientID     string
	clientSecret string
	credsRepo    CredentialStore
}

func NewService(baseURL string, httpClient *http.Client, clientID, clientSecret string, credsRepo CredentialStore) *Service {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Service{
		baseURL:      strings.TrimSpace(baseURL),
		http:         httpClient,
		clientID:     strings.TrimSpace(clientID),
		clientSecret: strings.TrimSpace(clientSecret),
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
	token, _, err := client.AuthenticatePassword(ctx, creds.Email, creds.Password, true)
	if err != nil {
		return nil, "", err
	}
	return client, token.AccessToken, nil
}

func (s *Service) GeneratePasscode(ctx context.Context, req PasscodeRequest) (*PasscodeResponse, error) {
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
		// err != nil {
		// 	return nil, err
		// }
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

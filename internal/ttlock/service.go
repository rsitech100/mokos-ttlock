package ttlock

import (
	"context"
	"errors"
	"time"
)

type Service struct {
	client         *Client
	username       string
	passwordMD5Hex string
}

func NewService(client *Client, username, passwordMD5Hex string) *Service {
	return &Service{
		client:         client,
		username:       username,
		passwordMD5Hex: passwordMD5Hex,
	}
}

type PasscodeRequest struct {
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

func (s *Service) getAccessToken(ctx context.Context) (string, error) {
	if s.username == "" || s.passwordMD5Hex == "" {
		return "", errors.New("service missing credentials")
	}

	token, _, err := s.client.AuthenticatePassword(ctx, s.username, s.passwordMD5Hex, true)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func (s *Service) GeneratePasscode(ctx context.Context, req PasscodeRequest) (*PasscodeResponse, error) {
	accessToken, err := s.getAccessToken(ctx)
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
		result, err = s.client.ChangeKeyboardPassword(ctx, params)
	} else {
		result, err = s.client.AddKeyboardPassword(ctx, params)
	}
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

func (s *Service) ReplacePasscode(ctx context.Context, req PasscodeRequest) (*PasscodeResponse, error) {
	accessToken, err := s.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	if req.PasscodeID > 0 {
		if err := s.client.DeleteKeyboardPassword(ctx, KeyboardPwdDeleteRequest{
			LockID:        req.LockID,
			KeyboardPwdID: req.PasscodeID,
			AccessToken:   accessToken,
		}); err != nil {
			return nil, err
		}
	}

	result, err := s.client.AddKeyboardPassword(ctx, KeyboardPwdRequest{
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

	return &PasscodeResponse{
		ID:        result.KeyboardPwdID,
		Passcode:  result.KeyboardPwd,
		ExpiresAt: req.End,
		StartsAt:  req.Start,
	}, nil
}

func (s *Service) DeletePasscode(ctx context.Context, lockID, passcodeID int64) error {
	accessToken, err := s.getAccessToken(ctx)
	if err != nil {
		return err
	}
	return s.client.DeleteKeyboardPassword(ctx, KeyboardPwdDeleteRequest{
		LockID:        lockID,
		KeyboardPwdID: passcodeID,
		AccessToken:   accessToken,
	})
}

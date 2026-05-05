package ttlock

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL       string
	ClientID      string
	ClientSecret  string
	HTTP          *http.Client
	tokenEndpoint string
}

const (
	ttlockHTTPMaxAttempts = 3
	ttlockRetryBackoff    = 250 * time.Millisecond
)

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	UID              int64  `json:"uid"`
	ErrCode          int64  `json:"errcode"`
	ErrMsg           string `json:"errmsg"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type keyboardPwdResponse struct {
	KeyboardPwdID int64  `json:"keyboardPwdId"`
	KeyboardPwd   string `json:"keyboardPwd"`
	ErrCode       int64  `json:"errcode"`
	ErrMsg        string `json:"errmsg"`
}

type ttlockOperationResponse struct {
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	CardID  int64  `json:"cardId"`
}

type identityCard struct {
	CardID     int64  `json:"cardId"`
	CardNumber string `json:"cardNumber"`
}

type identityCardListResponse struct {
	List     []identityCard `json:"list"`
	PageNo   int            `json:"pageNo"`
	PageSize int            `json:"pageSize"`
	Pages    int            `json:"pages"`
	Total    int            `json:"total"`
	ErrCode  int64          `json:"errcode"`
	ErrMsg   string         `json:"errmsg"`
}

var ErrCardNumberNotFound = errors.New("card_number not found on lock")

func IsCardNumberNotFound(err error) bool {
	return errors.Is(err, ErrCardNumberNotFound)
}

func NewClient(baseURL, clientID, clientSecret string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	if baseURL == "" {
		baseURL = "https://api.ttlock.com"
	}

	return &Client{
		BaseURL:       strings.TrimSuffix(baseURL, "/"),
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		HTTP:          httpClient,
		tokenEndpoint: "/oauth2/token",
	}
}

func (c *Client) Authenticate(ctx context.Context) (string, time.Time, error) {
	values := url.Values{}
	values.Set("client_id", c.ClientID)
	values.Set("client_secret", c.ClientSecret)
	values.Set("grant_type", "client_credentials")

	endpoint := c.BaseURL + c.tokenEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("token request failed: %s", strings.TrimSpace(string(body)))
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return "", time.Time{}, fmt.Errorf("decode token response: %w", err)
	}

	if token.AccessToken == "" {
		if token.ErrCode != 0 || token.ErrMsg != "" {
			return "", time.Time{}, fmt.Errorf("token request rejected: errcode=%d errmsg=%s", token.ErrCode, strings.TrimSpace(token.ErrMsg))
		}
		if token.Error != "" || token.ErrorDescription != "" {
			return "", time.Time{}, fmt.Errorf("token request rejected: %s (%s)", strings.TrimSpace(token.Error), strings.TrimSpace(token.ErrorDescription))
		}
		return "", time.Time{}, fmt.Errorf("empty access token, raw response: %s", strings.TrimSpace(string(body)))
	}

	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return token.AccessToken, expiresAt, nil
}

// AuthenticatePassword performs the password grant: username (email) + MD5 password.
func (c *Client) AuthenticatePassword(ctx context.Context, username, password string, alreadyMD5 bool) (*tokenResponse, time.Time, error) {
	if username == "" || password == "" {
		return nil, time.Time{}, errors.New("username and password are required")
	}

	if !alreadyMD5 {
		sum := md5.Sum([]byte(password))
		password = hex.EncodeToString(sum[:])
	}

	values := url.Values{}
	values.Set("client_id", c.ClientID)
	values.Set("client_secret", c.ClientSecret)
	values.Set("username", username)
	values.Set("password", password)
	values.Set("grant_type", "password")

	endpoint := c.BaseURL + c.tokenEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, time.Time{}, fmt.Errorf("token request failed: %s", strings.TrimSpace(string(body)))
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, time.Time{}, fmt.Errorf("decode token response: %w", err)
	}

	if token.AccessToken == "" {
		if token.ErrCode != 0 || token.ErrMsg != "" {
			return nil, time.Time{}, fmt.Errorf("token request rejected: errcode=%d errmsg=%s", token.ErrCode, strings.TrimSpace(token.ErrMsg))
		}
		if token.Error != "" || token.ErrorDescription != "" {
			return nil, time.Time{}, fmt.Errorf("token request rejected: %s (%s)", strings.TrimSpace(token.Error), strings.TrimSpace(token.ErrorDescription))
		}
		return nil, time.Time{}, fmt.Errorf("empty access token, raw response: %s", strings.TrimSpace(string(body)))
	}

	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return &token, expiresAt, nil
}

type KeyboardPwdRequest struct {
	LockID        int64
	KeyboardPwdID int64
	Name          string
	Start         time.Time
	End           time.Time
	KeyboardPwd   string
	CardNumber    string
	AccessToken   string
}

type KeyboardPwdDeleteRequest struct {
	LockID        int64
	KeyboardPwdID int64
	AccessToken   string
}

func parseTTLockTime(s string) (int64, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, err
	}
	return t.Truncate(time.Hour).UnixMilli(), nil
}

func (c *Client) AddKeyboardPassword(
	ctx context.Context,
	req KeyboardPwdRequest,
) (*keyboardPwdResponse, error) {

	if req.AccessToken == "" {
		return nil, errors.New("access token is required")
	}
	if req.KeyboardPwd == "" {
		return nil, errors.New("keyboardPwd is required")
	}

	// start := alignToHour(req.Start)
	// end := alignToHour(req.End)

	form := url.Values{}
	form.Set("clientId", c.ClientID)
	form.Set("accessToken", req.AccessToken)
	form.Set("lockId", strconv.FormatInt(req.LockID, 10))
	form.Set("keyboardPwd", req.KeyboardPwd)
	form.Set("keyboardPwdName", req.Name)
	form.Set("startDate", strconv.FormatInt(req.Start.UnixMilli(), 10))
	form.Set("endDate", strconv.FormatInt(req.End.UnixMilli(), 10))
	if req.CardNumber != "" {
		form.Set("cardNumber", req.CardNumber)
	}
	form.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))
	form.Set("addType", "2") // kalau pakai gateway

	endpoint := c.BaseURL + "/v3/keyboardPwd/add"

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf(
			"add keyboard password failed (%d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	return decodeKeyboardPwdResponse(body, 0, req.KeyboardPwd)
}

func (c *Client) ChangeKeyboardPassword(
	ctx context.Context,
	req KeyboardPwdRequest,
) (*keyboardPwdResponse, error) {
	if req.AccessToken == "" {
		return nil, errors.New("access token is required")
	}
	if req.KeyboardPwdID <= 0 {
		return nil, errors.New("keyboardPwdId is required")
	}
	if req.KeyboardPwd == "" {
		return nil, errors.New("keyboardPwd is required")
	}

	form := url.Values{}
	form.Set("clientId", c.ClientID)
	form.Set("accessToken", req.AccessToken)
	form.Set("lockId", strconv.FormatInt(req.LockID, 10))
	form.Set("keyboardPwdId", strconv.FormatInt(req.KeyboardPwdID, 10))
	form.Set("newKeyboardPwd", req.KeyboardPwd)
	form.Set("keyboardPwdName", req.Name)
	form.Set("startDate", strconv.FormatInt(req.Start.UnixMilli(), 10))
	form.Set("endDate", strconv.FormatInt(req.End.UnixMilli(), 10))
	if req.CardNumber != "" {
		form.Set("cardNumber", req.CardNumber)
	}
	form.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	endpoint := c.BaseURL + "/v3/keyboardPwd/change"
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf(
			"change keyboard password failed (%d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	return decodeKeyboardPwdResponse(body, req.KeyboardPwdID, req.KeyboardPwd)
}

func (c *Client) DeleteKeyboardPassword(
	ctx context.Context,
	req KeyboardPwdDeleteRequest,
) error {
	if req.AccessToken == "" {
		return errors.New("access token is required")
	}
	if req.LockID <= 0 {
		return errors.New("lockId is required")
	}
	if req.KeyboardPwdID <= 0 {
		return errors.New("keyboardPwdId is required")
	}

	form := url.Values{}
	form.Set("clientId", c.ClientID)
	form.Set("accessToken", req.AccessToken)
	form.Set("lockId", strconv.FormatInt(req.LockID, 10))
	form.Set("keyboardPwdId", strconv.FormatInt(req.KeyboardPwdID, 10))
	form.Set("deleteType", "2")
	form.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	endpoint := c.BaseURL + "/v3/keyboardPwd/delete"
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf(
			"delete keyboard password failed (%d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var result ttlockOperationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("ttlock rejected delete request: errcode=%d errmsg=%s raw=%s", result.ErrCode, strings.TrimSpace(result.ErrMsg), strings.TrimSpace(string(body)))
	}

	return nil
}

func (c *Client) ChangeCardPeriodByNumber(
	ctx context.Context,
	lockID int64,
	cardNumber string,
	start time.Time,
	end time.Time,
	accessToken string,
) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}
	if lockID <= 0 {
		return errors.New("lockId is required")
	}
	cardNumber = strings.TrimSpace(cardNumber)
	if cardNumber == "" {
		return errors.New("cardNumber is required")
	}

	cardID, err := c.findCardIDByNumber(ctx, lockID, cardNumber, accessToken)
	if err != nil {
		return err
	}

	form := url.Values{}
	form.Set("clientId", c.ClientID)
	form.Set("accessToken", accessToken)
	form.Set("lockId", strconv.FormatInt(lockID, 10))
	form.Set("cardId", strconv.FormatInt(cardID, 10))
	form.Set("startDate", strconv.FormatInt(start.UnixMilli(), 10))
	form.Set("endDate", strconv.FormatInt(end.UnixMilli(), 10))
	form.Set("changeType", "2")
	form.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	endpoint := c.BaseURL + "/v3/identityCard/changePeriod"
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf(
			"change card period failed (%d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var result ttlockOperationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("ttlock rejected card period update: errcode=%d errmsg=%s raw=%s", result.ErrCode, strings.TrimSpace(result.ErrMsg), strings.TrimSpace(string(body)))
	}

	return nil
}

func (c *Client) AddCardByNumber(
	ctx context.Context,
	lockID int64,
	cardNumber, cardName string,
	start time.Time,
	end time.Time,
	accessToken string,
) (int64, error) {
	if accessToken == "" {
		return 0, errors.New("access token is required")
	}
	if lockID <= 0 {
		return 0, errors.New("lockId is required")
	}
	cardNumber = strings.TrimSpace(cardNumber)
	if cardNumber == "" {
		return 0, errors.New("cardNumber is required")
	}

	form := url.Values{}
	form.Set("clientId", c.ClientID)
	form.Set("accessToken", accessToken)
	form.Set("lockId", strconv.FormatInt(lockID, 10))
	form.Set("cardNumber", cardNumber)
	if strings.TrimSpace(cardName) != "" {
		form.Set("cardName", strings.TrimSpace(cardName))
	}
	form.Set("startDate", strconv.FormatInt(start.UnixMilli(), 10))
	form.Set("endDate", strconv.FormatInt(end.UnixMilli(), 10))
	form.Set("addType", "2")
	form.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	endpoint := c.BaseURL + "/v3/identityCard/add"
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf(
			"add card failed (%d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var result ttlockOperationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	if result.ErrCode != 0 {
		return 0, fmt.Errorf("ttlock rejected add card request: errcode=%d errmsg=%s raw=%s", result.ErrCode, strings.TrimSpace(result.ErrMsg), strings.TrimSpace(string(body)))
	}
	if result.CardID <= 0 {
		return 0, fmt.Errorf("ttlock response missing cardId: %s", strings.TrimSpace(string(body)))
	}

	return result.CardID, nil
}

func (c *Client) DeleteCardByNumber(
	ctx context.Context,
	lockID int64,
	cardNumber string,
	accessToken string,
) (int64, error) {
	if accessToken == "" {
		return 0, errors.New("access token is required")
	}
	if lockID <= 0 {
		return 0, errors.New("lockId is required")
	}
	cardNumber = strings.TrimSpace(cardNumber)
	if cardNumber == "" {
		return 0, errors.New("cardNumber is required")
	}

	cardID, err := c.findCardIDByNumber(ctx, lockID, cardNumber, accessToken)
	if err != nil {
		return 0, err
	}

	form := url.Values{}
	form.Set("clientId", c.ClientID)
	form.Set("accessToken", accessToken)
	form.Set("lockId", strconv.FormatInt(lockID, 10))
	form.Set("cardId", strconv.FormatInt(cardID, 10))
	form.Set("deleteType", "2")
	form.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	endpoint := c.BaseURL + "/v3/identityCard/delete"
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf(
			"delete card failed (%d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var result ttlockOperationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	if result.ErrCode != 0 {
		return 0, fmt.Errorf("ttlock rejected delete card request: errcode=%d errmsg=%s raw=%s", result.ErrCode, strings.TrimSpace(result.ErrMsg), strings.TrimSpace(string(body)))
	}

	return cardID, nil
}

func (c *Client) findCardIDByNumber(ctx context.Context, lockID int64, cardNumber, accessToken string) (int64, error) {
	params := url.Values{}
	params.Set("clientId", c.ClientID)
	params.Set("accessToken", accessToken)
	params.Set("lockId", strconv.FormatInt(lockID, 10))
	params.Set("pageNo", "1")
	params.Set("pageSize", "100")
	params.Set("date", strconv.FormatInt(time.Now().UnixMilli(), 10))

	endpoint := c.BaseURL + "/v3/identityCard/list?" + params.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("get card list failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result identityCardListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("decode card list response: %w", err)
	}

	if result.ErrCode != 0 {
		return 0, fmt.Errorf("ttlock rejected card list request: errcode=%d errmsg=%s raw=%s", result.ErrCode, strings.TrimSpace(result.ErrMsg), strings.TrimSpace(string(body)))
	}

	for _, card := range result.List {
		if strings.TrimSpace(card.CardNumber) == cardNumber {
			if card.CardID <= 0 {
				return 0, fmt.Errorf("ttlock card data missing cardId for card_number=%s", cardNumber)
			}
			return card.CardID, nil
		}
	}

	return 0, fmt.Errorf("%w: card_number %s not found on lock %d", ErrCardNumberNotFound, cardNumber, lockID)
}

func decodeKeyboardPwdResponse(body []byte, fallbackID int64, fallbackPwd string) (*keyboardPwdResponse, error) {
	var result keyboardPwdResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.ErrCode != 0 {
		return nil, fmt.Errorf("ttlock rejected request: errcode=%d errmsg=%s raw=%s", result.ErrCode, strings.TrimSpace(result.ErrMsg), strings.TrimSpace(string(body)))
	}

	if result.KeyboardPwdID == 0 {
		result.KeyboardPwdID = fallbackID
	}
	if result.KeyboardPwd == "" {
		result.KeyboardPwd = fallbackPwd
	}
	if result.KeyboardPwdID == 0 {
		return nil, fmt.Errorf("ttlock response missing keyboardPwdId: %s", strings.TrimSpace(string(body)))
	}

	return &result, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}

	canReplayBody := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	backoff := ttlockRetryBackoff

	for attempt := 1; attempt <= ttlockHTTPMaxAttempts; attempt++ {
		callReq, err := cloneRequest(req)
		if err != nil {
			return nil, err
		}

		resp, err := c.HTTP.Do(callReq)
		if err == nil {
			return resp, nil
		}

		if !isRetryableTransportError(err) || attempt == ttlockHTTPMaxAttempts || !canReplayBody {
			return nil, err
		}

		timer := time.NewTimer(backoff)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		case <-timer.C:
			backoff *= 2
		}
	}

	return nil, errors.New("request failed after retries")
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	cloned := req.Clone(req.Context())
	if req.GetBody == nil {
		return cloned, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("clone request body: %w", err)
	}
	cloned.Body = body
	return cloned, nil
}

func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	msg := strings.ToLower(err.Error())
	retryableSnippets := []string{
		"socket hang up",
		"connection reset by peer",
		"broken pipe",
		"unexpected eof",
		"use of closed network connection",
		"server closed idle connection",
	}
	for _, snippet := range retryableSnippets {
		if strings.Contains(msg, snippet) {
			return true
		}
	}

	return false
}

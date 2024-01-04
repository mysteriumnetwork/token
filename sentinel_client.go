package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type SentinelClient struct {
	cfg    SentinelClientConfig
	client *http.Client

	pkLock    sync.Mutex
	publicKey []byte

	lock       sync.Mutex
	token      string
	validUntil time.Time
}

type SentinelClientConfig struct {
	SentinelUrl string

	//auth token config
	Username string
	Password string
	Pool     string
}

func NewSentinelClient(cfg SentinelClientConfig, timeout time.Duration) *SentinelClient {
	return &SentinelClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

type PublicKey struct {
	Key string `json:"key_base64"`
}

func (s *SentinelClient) GetPublicKey() ([]byte, error) {
	s.pkLock.Lock()
	defer s.pkLock.Unlock()

	if len(s.publicKey) > 0 {
		return s.publicKey, nil
	}

	resp, err := s.client.Get(fmt.Sprintf("%s/api/v1/auth/public/key", strings.TrimSuffix(s.cfg.SentinelUrl, "/")))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	var pb PublicKey
	if err = json.Unmarshal(body, &pb); err != nil {
		return nil, fmt.Errorf("could not unmarshal response body: %w", err)
	}

	got, err := base64.StdEncoding.DecodeString(pb.Key)
	if err != nil {
		return nil, err
	}
	s.publicKey = got

	return s.publicKey, nil
}

type Token struct {
	Token string `json:"token"`
}

func (s *SentinelClient) Valid(jwtToken string) (bool, error) {
	tokenBody, err := json.Marshal(Token{Token: jwtToken})
	if err != nil {
		return false, err
	}
	resp, err := s.client.Post(fmt.Sprintf("%s/api/v1/token/validate", s.cfg.SentinelUrl), "application/json", strings.NewReader(string(tokenBody)))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode < 500 {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil
	}
	return false, fmt.Errorf("failed to validate token: %s", string(body))
}

func (s *SentinelClient) GetAuthToken() (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.token == "" || s.validUntil.Before(time.Now()) {
		err := s.loadAuthToken()
		if err != nil {
			return "", fmt.Errorf("failed to load token: %w", err)
		}
	}
	return s.token, nil
}

type LoginRequest struct {
	Username string `json:"username"`
	UserUUID string `json:"user_uuid"`
	Password string `json:"password"`
	Pool     string `json:"pool"`
}

type LoginResponse struct {
	AuthToken    string `json:"auth_token"`
	RefreshToken string `json:"refresh_token"`
}

func (s *SentinelClient) loadAuthToken() error {
	url := fmt.Sprintf("%s/api/v1/auth/password", s.cfg.SentinelUrl)

	req := LoginRequest{
		Username: s.cfg.Username,
		Password: s.cfg.Password,
		Pool:     s.cfg.Pool,
	}
	blob, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("could not marshal request body: %w", err)
	}
	resp, err := s.client.Post(url, "application/json", bytes.NewBuffer(blob))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("sentinel responded with non 200 code: %s", string(body))
	}

	var r *LoginResponse
	if err = json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("could not unmarshal response body: %w", err)
	}

	s.token = r.AuthToken
	expirationTime, err := s.getExpirationTime(s.token)
	if err != nil {
		return fmt.Errorf("could not get expiration time: %w", err)
	}
	s.validUntil = expirationTime.Add(-10 * time.Minute)
	return nil
}

func (s *SentinelClient) getExpirationTime(authToken string) (time.Time, error) {
	publicKey, err := s.GetPublicKey()
	if err != nil {
		return time.Time{}, fmt.Errorf("could not get public key: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	token, err := jwt.Parse(authToken, func(jwtToken *jwt.Token) (any, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method %q", jwtToken.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return time.Time{}, fmt.Errorf("invalid token")
	}
	expirationTime, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid expiration time")
	}

	return time.Unix(int64(expirationTime), 0), nil
}

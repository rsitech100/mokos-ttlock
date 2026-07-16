package ttlock

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Credential struct {
	ID             string
	Email          string
	Password       string
	AccessToken    sql.NullString
	TokenExpiresAt sql.NullTime
}

type CredentialStore interface {
	GetActiveByKostID(ctx context.Context, kostID string) (Credential, error)
	SaveToken(ctx context.Context, id string, accessToken string, expiresAt time.Time) error
}

type PostgresCredentialStore struct {
	db *sql.DB
}

func NewPostgresCredentialStore(db *sql.DB) *PostgresCredentialStore {
	return &PostgresCredentialStore{db: db}
}

func (s *PostgresCredentialStore) GetActiveByKostID(ctx context.Context, kostID string) (Credential, error) {
	if strings.TrimSpace(kostID) == "" {
		return Credential{}, errors.New("kost_id is required")
	}

	const q = `
SELECT
	id,
	email,
	"password",
	access_token,
	token_expires_at
FROM public.ttlock_integrations
WHERE kostid = $1::uuid
  AND status = 'active'
ORDER BY "updatedAt" DESC
LIMIT 1
`

	var c Credential
	err := s.db.QueryRowContext(ctx, q, kostID).Scan(
		&c.ID,
		&c.Email,
		&c.Password,
		&c.AccessToken,
		&c.TokenExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Credential{}, fmt.Errorf("active ttlock integration not found for kost_id=%s", kostID)
		}
		return Credential{}, fmt.Errorf("query ttlock integration: %w", err)
	}

	c.Email = strings.TrimSpace(c.Email)
	c.Password = strings.TrimSpace(c.Password)

	if c.Email == "" || c.Password == "" {
		return Credential{}, errors.New("ttlock integration has incomplete account credentials")
	}

	return c, nil
}

func (s *PostgresCredentialStore) SaveToken(ctx context.Context, id string, accessToken string, expiresAt time.Time) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("id is required")
	}

	const q = `
UPDATE public.ttlock_integrations
SET access_token = $1,
    token_expires_at = $2,
    "updatedAt" = now()
WHERE id = $3::uuid
`

	_, err := s.db.ExecContext(ctx, q, accessToken, expiresAt, id)
	if err != nil {
		return fmt.Errorf("save ttlock token: %w", err)
	}

	return nil
}

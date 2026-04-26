package ttlock

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Credential struct {
	ClientID     string
	ClientSecret string
	Email        string
	Password     string
}

type CredentialStore interface {
	GetActiveByKostID(ctx context.Context, kostID string) (Credential, error)
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
	client_id,
	secret_key,
	email,
	"password"
FROM public.ttlock_integrations
WHERE kostid = $1::uuid
  AND status = 'active'
ORDER BY "updatedAt" DESC
LIMIT 1
`

	var c Credential
	err := s.db.QueryRowContext(ctx, q, kostID).Scan(
		&c.ClientID,
		&c.ClientSecret,
		&c.Email,
		&c.Password,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Credential{}, fmt.Errorf("active ttlock integration not found for kost_id=%s", kostID)
		}
		return Credential{}, fmt.Errorf("query ttlock integration: %w", err)
	}

	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	c.Email = strings.TrimSpace(c.Email)
	c.Password = strings.TrimSpace(c.Password)

	if c.ClientID == "" || c.ClientSecret == "" || c.Email == "" || c.Password == "" {
		return Credential{}, errors.New("ttlock integration has incomplete credentials")
	}

	return c, nil
}

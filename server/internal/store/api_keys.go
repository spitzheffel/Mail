package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/amine123max/Mail/server/internal/model"
)

const MaxAPIKeysPerUser = 10

var ErrAPIKeyLimitReached = errors.New("API_KEY_LIMIT_REACHED")

func (s *Store) InsertAPIKey(ctx context.Context, userID int64, name, prefix, tokenHash string) (*model.APIKey, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var existing int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_keys WHERE user_id=?", userID).Scan(&existing); err != nil {
		return nil, err
	}
	if existing >= MaxAPIKeysPerUser {
		return nil, ErrAPIKeyLimitReached
	}
	createdAt := nowISO()
	result, err := tx.ExecContext(ctx, `INSERT INTO api_keys (user_id,name,prefix,token_hash,created_at)
		VALUES(?,?,?,?,?)`, userID, name, prefix, tokenHash, createdAt)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &model.APIKey{ID: id, Name: name, Prefix: prefix, CreatedAt: createdAt}, nil
}

func (s *Store) ListAPIKeys(ctx context.Context, userID int64) ([]model.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,prefix,created_at,last_used_at
		FROM api_keys WHERE user_id=? ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]model.APIKey, 0)
	for rows.Next() {
		var key model.APIKey
		if err := rows.Scan(&key.ID, &key.Name, &key.Prefix, &key.CreatedAt, &key.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) DeleteAPIKey(ctx context.Context, userID, id int64) (bool, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id=? AND user_id=?", id, userID)
	if err != nil {
		return false, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return deleted == 1, nil
}

func (s *Store) APIKeyTokenHashExists(ctx context.Context, tokenHash string) (bool, error) {
	var present int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM api_keys WHERE token_hash=?", tokenHash).Scan(&present)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

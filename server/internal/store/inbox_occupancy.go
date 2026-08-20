package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/amine123max/Mail/server/internal/model"
)

const InboxLeaseTTL = 30 * time.Minute

var (
	ErrInboxPoolExhausted = errors.New("INBOX_POOL_EXHAUSTED")
	ErrInboxLeaseNotFound = errors.New("INBOX_LEASE_NOT_FOUND")
)

func (s *Store) expireLeasedOccupancies(ctx context.Context, tx *sql.Tx, now string) error {
	_, err := tx.ExecContext(ctx, `UPDATE inbox_occupancies SET status=?, updated_at=?
		WHERE status=? AND expires_at IS NOT NULL AND expires_at<=?`,
		model.InboxOccupancyReleased, now, model.InboxOccupancyLeased, now)
	return err
}

func newLeaseID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "ls_" + hex.EncodeToString(value), nil
}

func (s *Store) LeaseInbox(ctx context.Context, userID, apiKeyID int64, group, platform string) (*model.InboxOccupancy, error) {
	ownerKey := "user:" + strconv.FormatInt(userID, 10)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	now := nowISO()
	if err := s.expireLeasedOccupancies(ctx, tx, now); err != nil {
		return nil, err
	}
	row := tx.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts
		WHERE owner_key=? AND group_name=? AND id NOT IN (
			SELECT account_id FROM inbox_occupancies WHERE platform=? AND status IN (?,?)
		) ORDER BY sort_order ASC, id ASC LIMIT 1`,
		ownerKey, group, platform, model.InboxOccupancyLeased, model.InboxOccupancyOccupied)
	account, err := scanStoredAccount(row)
	if err == sql.ErrNoRows {
		return nil, ErrInboxPoolExhausted
	}
	if err != nil {
		return nil, err
	}
	public, err := s.publicAccount(account)
	if err != nil {
		return nil, err
	}
	leaseID, err := newLeaseID()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(InboxLeaseTTL).Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `INSERT INTO inbox_occupancies
		(lease_id,user_id,api_key_id,account_id,platform,group_name,status,created_at,updated_at,expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		leaseID, userID, apiKeyID, account.ID, platform, group, model.InboxOccupancyLeased, now, now, expiresAt)
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
	return &model.InboxOccupancy{
		ID: id, LeaseID: leaseID, UserID: userID, APIKeyID: &apiKeyID, AccountID: account.ID,
		Platform: platform, GroupName: group, Status: model.InboxOccupancyLeased,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: &expiresAt, Email: public.Email,
	}, nil
}

func (s *Store) ActiveInboxLease(ctx context.Context, apiKeyID int64, leaseID string) (*model.InboxOccupancy, error) {
	now := nowISO()
	if _, err := s.db.ExecContext(ctx, `UPDATE inbox_occupancies SET status=?, updated_at=?
		WHERE lease_id=? AND status=? AND expires_at IS NOT NULL AND expires_at<=?`,
		model.InboxOccupancyReleased, now, leaseID, model.InboxOccupancyLeased, now); err != nil {
		return nil, err
	}
	return s.getInboxOccupancy(ctx, `SELECT o.id,o.lease_id,o.user_id,o.api_key_id,o.account_id,o.platform,o.group_name,o.status,o.created_at,o.updated_at,o.expires_at,a.email_encrypted
		FROM inbox_occupancies o JOIN accounts a ON a.id=o.account_id
		WHERE o.lease_id=? AND o.api_key_id=? AND o.status=?`, leaseID, apiKeyID, model.InboxOccupancyLeased)
}

func (s *Store) CompleteInboxLease(ctx context.Context, apiKeyID int64, leaseID string) (*model.InboxOccupancy, error) {
	return s.transitionInboxLease(ctx, apiKeyID, leaseID, model.InboxOccupancyOccupied, true)
}

func (s *Store) ReleaseInboxLease(ctx context.Context, apiKeyID int64, leaseID string) (*model.InboxOccupancy, error) {
	return s.transitionInboxLease(ctx, apiKeyID, leaseID, model.InboxOccupancyReleased, false)
}

func (s *Store) transitionInboxLease(ctx context.Context, apiKeyID int64, leaseID, status string, clearExpiry bool) (*model.InboxOccupancy, error) {
	now := nowISO()
	if _, err := s.db.ExecContext(ctx, `UPDATE inbox_occupancies SET status=?, updated_at=?
		WHERE lease_id=? AND status=? AND expires_at IS NOT NULL AND expires_at<=?`,
		model.InboxOccupancyReleased, now, leaseID, model.InboxOccupancyLeased, now); err != nil {
		return nil, err
	}
	var result sql.Result
	var err error
	if clearExpiry {
		result, err = s.db.ExecContext(ctx, `UPDATE inbox_occupancies SET status=?, expires_at=NULL, updated_at=?
			WHERE lease_id=? AND api_key_id=? AND status=?`, status, now, leaseID, apiKeyID, model.InboxOccupancyLeased)
	} else {
		result, err = s.db.ExecContext(ctx, `UPDATE inbox_occupancies SET status=?, updated_at=?
			WHERE lease_id=? AND api_key_id=? AND status=?`, status, now, leaseID, apiKeyID, model.InboxOccupancyLeased)
	}
	if err != nil {
		return nil, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if updated != 1 {
		return nil, ErrInboxLeaseNotFound
	}
	return s.getInboxOccupancy(ctx, `SELECT o.id,o.lease_id,o.user_id,o.api_key_id,o.account_id,o.platform,o.group_name,o.status,o.created_at,o.updated_at,o.expires_at,a.email_encrypted
		FROM inbox_occupancies o JOIN accounts a ON a.id=o.account_id
		WHERE o.lease_id=? AND o.api_key_id=?`, leaseID, apiKeyID)
}

func (s *Store) getInboxOccupancy(ctx context.Context, query string, args ...any) (*model.InboxOccupancy, error) {
	var occupancy model.InboxOccupancy
	var apiKeyID sql.NullInt64
	var expiresAt sql.NullString
	var emailEncrypted string
	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&occupancy.ID, &occupancy.LeaseID, &occupancy.UserID, &apiKeyID, &occupancy.AccountID,
		&occupancy.Platform, &occupancy.GroupName, &occupancy.Status, &occupancy.CreatedAt, &occupancy.UpdatedAt,
		&expiresAt, &emailEncrypted,
	)
	if err == sql.ErrNoRows {
		return nil, ErrInboxLeaseNotFound
	}
	if err != nil {
		return nil, err
	}
	if apiKeyID.Valid {
		id := apiKeyID.Int64
		occupancy.APIKeyID = &id
	}
	if expiresAt.Valid {
		value := expiresAt.String
		occupancy.ExpiresAt = &value
	}
	email, err := s.box.Decrypt(emailEncrypted)
	if err != nil {
		return nil, err
	}
	occupancy.Email = email
	return &occupancy, nil
}

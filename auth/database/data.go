package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type User struct {
	ID          uuid.UUID
	Email       string
	Password    string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   sql.NullTime
	IsConfirmed bool
}

type Token struct {
	ID           int
	AccessToken  string
	RefreshToken string
	UserID       uuid.UUID
}

type CodeSignature struct {
	Code      string
	Signature string
	UserID    uuid.UUID
	IsUsed    bool
	ExpiresAt time.Time
}

type Database struct {
	db           *sql.DB
	queryTimeout time.Duration
}

func NewDatabase(connectionString string, queryTimeout time.Duration) (*Database, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{db: db, queryTimeout: queryTimeout}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) Migrate() error {
	createTablesSQL := `
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMPTZ,
			is_confirmed BOOLEAN DEFAULT false
		);

		CREATE TABLE IF NOT EXISTS tokens (
			id SERIAL PRIMARY KEY,
			access_token VARCHAR NOT NULL,
			refresh_token VARCHAR NOT NULL,
			user_id UUID NOT NULL REFERENCES users(id)
		);

		CREATE TABLE IF NOT EXISTS codes_signatures (
			code UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			signature UUID NOT NULL,
			user_id UUID NOT NULL REFERENCES users(id),
			is_used BOOLEAN DEFAULT false,
			expires_at TIMESTAMPTZ NOT NULL
		);
	`

	_, err := d.db.Exec(createTablesSQL)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

func (d *Database) CreateUser(ctx context.Context, email, hashedPassword string) (*User, error) {
	existingUser, _ := d.GetUserByEmail(ctx, email)
	if existingUser != nil {
		return nil, fmt.Errorf("email already exists")
	}

	newUserID := uuid.New()
	insertUserSQL := `
        INSERT INTO users (id, email, password, updated_at)
        VALUES ($1, $2, $3, NOW())
        RETURNING created_at, updated_at
    `

	var user User
	user.ID = newUserID
	user.Email = email
	user.Password = hashedPassword

	err := d.db.QueryRowContext(ctx, insertUserSQL, user.ID, email, hashedPassword).
		Scan(&user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		log.Printf("Failed to insert user: %v", err)
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}

	return &user, nil
}

func (d *Database) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		SELECT email, password, created_at, updated_at, deleted_at, is_confirmed
		FROM users
		WHERE id = $1
	`

	row := d.db.QueryRowContext(ctx, query, id)

	var user User
	user.ID = id

	err := row.Scan(&user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.IsConfirmed)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found with id: %s", id)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (d *Database) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		SELECT id, password, created_at, updated_at, deleted_at, is_confirmed
		FROM users
		WHERE email = $1
	`

	row := d.db.QueryRowContext(ctx, query, email)

	var user User
	user.Email = email

	err := row.Scan(&user.ID, &user.Password, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.IsConfirmed)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found with email: %s", email)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (d *Database) UpdateUser(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		UPDATE users
		SET email = $2, password = $3, updated_at = NOW()
		WHERE id = $1
	`

	_, err := d.db.ExecContext(ctx, query, user.ID, user.Email, user.Password)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (d *Database) DeleteUser(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		DELETE FROM users
		WHERE id = $1
	`

	_, err := d.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

func (d *Database) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	return d.db.PingContext(ctx)
}

func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	return rows, nil
}

func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()
	return d.db.QueryRowContext(ctx, query, args...)
}

func (d *Database) Execute(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	result, err := d.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	return result, nil
}

func (d *Database) GetEmailBySignature(ctx context.Context, signature string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		SELECT u.email
		FROM users u
		JOIN codes_signatures cs ON u.id = cs.user_id
		WHERE cs.signature = $1
	`

	row := d.db.QueryRowContext(ctx, query, signature)

	var email string
	err := row.Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("user not found with signature: %s", signature)
		}
		return "", fmt.Errorf("failed to scan email: %w", err)
	}

	return email, nil
}

func (d *Database) UpdateUserSignature(ctx context.Context, userID uuid.UUID, signature string) error {
	code := uuid.New()

	updateSignatureSQL := `
        INSERT INTO codes_signatures (code, signature, user_id, expires_at)
        VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')
    `
	_, err := d.db.ExecContext(ctx, updateSignatureSQL, code, signature, userID)
	if err != nil {
		log.Printf("Failed to update user signature: %v", err)
		return fmt.Errorf("failed to update user signature: %w", err)
	}

	return nil
}

func (d *Database) StoreVerificationCode(ctx context.Context, email, code, signature string) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	log.Printf("saving the confirmation code in the database: %s, signature: %s для email: %s", code, signature, email)

	deleteQuery := `
		DELETE FROM codes_signatures WHERE user_id = (SELECT id FROM users WHERE email = $1)
	`
	_, err := d.db.ExecContext(ctx, deleteQuery, email)
	if err != nil {
		log.Printf("error deleting old code: %v", err)
		return fmt.Errorf("failed to delete old verification code: %w", err)
	}

	insertQuery := `
		INSERT INTO codes_signatures (code, signature, user_id, expires_at)
		VALUES ($1, $2, (SELECT id FROM users WHERE email = $3), NOW() + INTERVAL '10 minutes')
	`
	_, err = d.db.ExecContext(ctx, insertQuery, code, signature, email)
	if err != nil {
		log.Printf("error when saving verification code: %v", err)
		return fmt.Errorf("failed to store verification code: %w", err)
	}

	return nil
}

func (d *Database) GetVerificationCode(ctx context.Context, email string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		SELECT code
		FROM codes_signatures
		WHERE user_id = (SELECT id FROM users WHERE email = $1) AND is_used = false AND expires_at > NOW()
	`

	row := d.db.QueryRowContext(ctx, query, email)

	var code string
	err := row.Scan(&code)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("verification code not found or expired for email: %s", email)
		}
		return "", fmt.Errorf("failed to get verification code: %w", err)
	}

	return code, nil
}

func (d *Database) DeleteVerificationCode(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		UPDATE codes_signatures
		SET is_used = true
		WHERE user_id = (SELECT id FROM users WHERE email = $1)
	`

	_, err := d.db.ExecContext(ctx, query, email)
	if err != nil {
		return fmt.Errorf("failed to delete verification code: %w", err)
	}

	return nil
}

func (d *Database) StoreRefreshToken(ctx context.Context, email, accessToken, refreshToken string) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	log.Printf("save refresh token in database from email: %s", email)

	query := `
		INSERT INTO tokens (access_token, refresh_token, user_id)
		VALUES ($1, $2, (SELECT id FROM users WHERE email = $3))
	`
	_, err := d.db.ExecContext(ctx, query, accessToken, refreshToken, email)
	if err != nil {
		log.Printf("error from saving refresh token in database: %v", err)
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	log.Println("refresh token successfully saved to the database!")
	return nil
}

func (d *Database) GetRefreshToken(ctx context.Context, email string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		SELECT refresh_token
		FROM tokens
		WHERE user_id = (SELECT id FROM users WHERE email = $1)
	`

	row := d.db.QueryRowContext(ctx, query, email)

	var refreshToken string
	err := row.Scan(&refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("refresh token not found for email: %s", email)
		}
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}

	return refreshToken, nil
}

func (d *Database) DeleteRefreshToken(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, d.queryTimeout)
	defer cancel()

	query := `
		DELETE FROM tokens
		WHERE user_id = (SELECT id FROM users WHERE email = $1)
	`

	_, err := d.db.ExecContext(ctx, query, email)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

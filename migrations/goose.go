package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upGoose, downGoose)
}

func upGoose(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.
	return nil
}

func downGoose(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}

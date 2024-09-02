package encryptor

import (
	"database/sql"

	"github.com/ethangrant/mage-crypt/cfg"
)

type encryptor struct {
	Db        *sql.DB
	LatestKey cfg.Key
	EnvPath   string
	DryRun    bool
}

func NewEncryptor(db *sql.DB, latestKey cfg.Key, envPath string, dryRun bool) *encryptor {
	return &encryptor{
		Db:        db,
		LatestKey: latestKey,
		EnvPath:   envPath,
		DryRun:    dryRun,
	}
}

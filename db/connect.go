package db

import (
	"database/sql"
	"fmt"
	"github.com/ethangrant/mage-crypt/cfg"
	"github.com/sansecio/gocommerce"
)

// gets a db connection based on env.php config
func Connect(envPath string) (*sql.DB, error) {
	m2store, err := cfg.GetStoreConfig(envPath)
	if err != nil {
		fmt.Println("Failed to load store config from env.php: ", err.Error())
		return nil, err
	}

	db, err := gocommerce.ConnectDB(*m2store.DB)
	if err != nil {
		fmt.Println("Failed to connect to database: ", err.Error())
		return nil, err
	}

	return db, nil
}

package model

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/ethangrant/mage-crypt/cfg"
)

type CoreConfigDataModel struct {
	conn *sql.DB
}

type CoreConfigDataRow struct {
	ConfigId   int64
	Scope      string
	Scope_id   int
	Path       string
	Value      string
	Updated_at time.Time
}

// new instance of the core_config_data model
func NewCoreConfigDataModel(conn *sql.DB) *CoreConfigDataModel {
	return &CoreConfigDataModel{conn: conn}
}

func (c *CoreConfigDataModel) GetEncryptedValues(key cfg.Key) ([]CoreConfigDataRow, error) {
	const encryptedValuesQuery = `SELECT config_id,value
FROM core_config_data
WHERE (value LIKE '_:_:____%' OR value LIKE '__:_:____%')
  AND value NOT LIKE ?
  AND value NOT LIKE 'a:%'
  AND value NOT LIKE 's:%';`

	excludeLatestKey := fmt.Sprintf("%d:_:__%%%%", key.VersionId)
	stmt, err := c.conn.Prepare(encryptedValuesQuery)
	if err != nil {
		return nil, err
	}

	var encryptedConfigRows []CoreConfigDataRow

	rows, err := stmt.Query(excludeLatestKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var config CoreConfigDataRow
		if err := rows.Scan(&config.ConfigId, &config.Value); err != nil {
			return nil, err
		}

		encryptedConfigRows = append(encryptedConfigRows, config)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return encryptedConfigRows, nil
}

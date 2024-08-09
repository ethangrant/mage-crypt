package encryptor

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/ethangrant/mage-crypt/cfg"
	"github.com/ethangrant/mage-crypt/model"
	"github.com/ethangrant/mage-crypt/cipher"
)

func Config(db *sql.DB, key cfg.Key) error {
	configModel := model.NewCoreConfigDataModel(db)
	configRows, err := configModel.GetEncryptedValues(key)
	if err != nil {
		return err
	}

	rowCount := len(configRows)

	if rowCount == 0 {
		return errors.New("found 0 records to re-encrypt")
	}

	fmt.Printf("Found %d records to re-encrypt \n", rowCount);
	rencryptedRows := make([]model.CoreConfigDataRow, len(configRows))
	var errors []error;
	for _, configRow := range configRows {
		crypt, err := cipher.GetCipherByValue(configRow.Value)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		plaintext, err := crypt.Decrypt(configRow.Value, "")
	}

	// decrypt them
	// update records

	return nil
}

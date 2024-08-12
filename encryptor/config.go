package encryptor

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethangrant/mage-crypt/cfg"
	"github.com/ethangrant/mage-crypt/cipher"
	"github.com/ethangrant/mage-crypt/model"
)

// re-encrypt core_config_data.value column
func Config(db *sql.DB, latestKey cfg.Key, envPath string, dryRun bool) error {
	configModel := model.NewCoreConfigDataModel(db)
	configRows, err := configModel.GetEncryptedValues(latestKey)
	if err != nil {
		return err
	}

	rowCount := len(configRows)
	if rowCount == 0 {
		return errors.New("found 0 records to re-encrypt")
	}

	fmt.Printf("Found %d records to re-encrypt \n\n", rowCount)
	encryptedRows := processRows(configRows, latestKey, envPath)

	// dry-run quit early before inserts
	if dryRun {
		return nil
	}

	err = configModel.InsertMultipleEncryptedValues(encryptedRows)
	if err != nil {
		return fmt.Errorf("failed to insert re-encrypted values with error %v", err)
	}

	fmt.Println("Successfully re-encrypted core_config_data!")

	return nil
}


func processRows(configRows []model.CoreConfigDataRow, latestKey cfg.Key, envPath string) []model.CoreConfigDataRow {
	latestCipher := cipher.GetLatestCipher()
	rencryptedRows := []model.CoreConfigDataRow{}

	for _, configRow := range configRows {
		fmt.Println("path: ", configRow.Path)
		fmt.Println("ciphertext: ", configRow.Value)

		// get the correct cipher to decrypt config row
		crypt, err := cipher.GetCipherByValue(configRow.Value)
		if err != nil {
			fmt.Printf("Failed to get a cipher for value %s, got error %v \n\n", configRow.Value, err)
			continue
		}

		// get the appropriate key to decrypt the value, this comes from the first part of the encrypted record
		decryptKey, err := cfg.GetKeyByValue(envPath, configRow.Value)
		if err != nil {
			fmt.Printf("Failed to get key for value %s, got error %v \n\n", configRow.Value, err)
			continue
		}

		// decrypt to plaintext
		plaintext, err := crypt.Decrypt(configRow.Value, decryptKey.Value)
		if err != nil {
			fmt.Printf("Failed to decrypt value, got error %v \n\n", err)
			continue
		}

		// re-encrypt using latest m2 cipher and key
		ciphertext, err := latestCipher.Encrypt(plaintext, latestKey.Value, strconv.Itoa(latestKey.VersionId))
		if err != nil {
			fmt.Printf("Failed to encrypt value, got error %v \n\n", err)
			continue
		}

		configRow.Value = ciphertext
		rencryptedRows = append(rencryptedRows, configRow)

		// output details to user
		fmt.Println("plaintext: ", plaintext)
		fmt.Println("re-encrypted: ", ciphertext)

		fmt.Println()
	}

	return rencryptedRows
}
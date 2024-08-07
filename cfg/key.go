package cfg

import (
	"github.com/sansecio/gocommerce/phpcfg"
	"strings"
)

// load all crypt keys into slice
func GetCryptKeys(envPath string) ([]string, error) {
	config, err := phpcfg.ParsePath(envPath)
	if err != nil {
		return nil, err
	}

	keys := config["root.crypt.key"]
	keySlice := strings.Split(keys, "\n")

	return keySlice, nil
}

// grab latest key from config.php
func GetLatestKey(envPath string) (string, error) {
	keys, err := GetCryptKeys(envPath)
	if err != nil {
		return "", err
	}

	key := keys[len(keys)-1]

	return key, nil
}

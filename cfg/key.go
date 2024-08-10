package cfg

import (
	"errors"
	"strconv"
	"strings"

	"github.com/sansecio/gocommerce/phpcfg"
)

type Key struct {
	Value     string
	VersionId int
}

var keyCache map[int]Key

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
func GetLatestKey(envPath string) (Key, error) {
	keys, err := GetCryptKeys(envPath)
	if err != nil {
		return Key{Value: "", VersionId: 0}, err
	}

	keyVersion := len(keys) - 1
	keyValue := keys[keyVersion]

	key := Key{Value: keyValue, VersionId: keyVersion}

	return key, nil
}

// takes encrypted value and matches it to a crypt key using the first part of the string
func GetKeyByValue(envPath string, value string) (Key, error) {
	parts := strings.Split(value, ":")

	if !strings.Contains(value, ":") {
		return Key{Value: "", VersionId: 0}, errors.New("Key not found, value is invalid")
	}

	keyVersion, err := strconv.Atoi(parts[0])
	if err != nil {
		return Key{Value: "", VersionId: 0}, err
	}

	cachedKey, ok := keyCache[keyVersion]
	if ok {
		return cachedKey, nil
	}

	keys, err := GetCryptKeys(envPath)
	if err != nil {
		return Key{Value: "", VersionId: 0}, err
	}

	if keyCache == nil {
		keyCache = make(map[int]Key, len(keys))
	}

	for index, k := range keys {
		if keyVersion == index {
			key := Key{Value: k, VersionId: keyVersion}
			keyCache[keyVersion] = key

			return key, nil
		}
	}

	return Key{Value: "", VersionId: 0}, errors.New("no key found for version provided")
}

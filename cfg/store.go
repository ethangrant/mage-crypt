package cfg

import (
	"github.com/sansecio/gocommerce"
)

// utilise go commerce to get config and db connection
func GetStoreConfig(envPath string) (*gocommerce.StoreConfig, error) {
	m2store := gocommerce.AllPlatforms[1]
	storeConfig, err := m2store.ParseConfig(envPath)
	if err != nil {
		return nil, err
	}

	return storeConfig, nil
}

package cfg

import (
	"reflect"
	"testing"

	"github.com/sansecio/gocommerce"
)

type GetStoreConfigTestCase struct {
	name        string
	envPath     string
	storeConfig *gocommerce.StoreConfig
	wantErr     bool
}

func TestGetStoreConfig(t *testing.T) {
	testcases := []GetStoreConfigTestCase{
		{
			name:    "Valid env returns store config and db config",
			envPath: "../sample/envmultiplekeys.php",
			storeConfig: &gocommerce.StoreConfig{
				DB: &gocommerce.DBConfig{
					Host:   "127.0.0.1",
					User:   "root",
					Pass:   "root",
					Name:   "vanilla_m2",
					Prefix: "",
					Port:   40000,
				},
				AdminSlug: "admin_1s6y12",
			},
			wantErr: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			storeConfig, err := GetStoreConfig(tt.envPath)

			if (err != nil) && tt.wantErr == false {
				t.Errorf("Expected no error, instead got %v", err)
			}

			if !reflect.DeepEqual(storeConfig, tt.storeConfig) {
				t.Errorf("Store configs do not match, expected %v, got %v", tt.storeConfig, storeConfig)
			}
		})
	}
}

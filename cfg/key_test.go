package cfg

import (
	"reflect"
	"testing"
)

type GetCryptKeysTestCase struct {
	name    string
	envPath string
	keys    []string
	wantErr bool
}

func TestGetCryptKeys(t *testing.T) {
	testCases := []GetCryptKeysTestCase{
		{name: "successfully extract multiple keys from valid env.php", envPath: "../sample/envmultiplekeys.php", keys: []string{"ccf8bfc4c5dce8b87f6d6f03c7c4612b", "e331b68cf8e8646f09e6ddcad2d32d83"}, wantErr: false},
		{name: "env.php does not exist", envPath: "../dirdoesnotexist/env.php", keys: nil, wantErr: true},
		{name: "successfully extract single keys from valid env.php", envPath: "../sample/envsinglekey.php", keys: []string{"ccf8bfc4c5dce8b87f6d6f03c7c4612b"}, wantErr: false},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := GetCryptKeys(tt.envPath)
			if (err != nil) && (tt.wantErr == false) {
				t.Errorf("Expected no error, instead got %v", err)
				return
			}

			if !reflect.DeepEqual(keys, tt.keys) {
				t.Errorf("got keys %v, want %v", keys, tt.keys)
			}
		})
	}
}

type GetLatestKeyTestCase struct {
	name    string
	envPath string
	key     string
	wantErr bool
}

func TestGetLatestKey(t *testing.T) {
	testCases := []GetLatestKeyTestCase{
		{name: "successfully extract latest key from valid env.php with multiple keys", envPath: "../sample/envmultiplekeys.php", key: "e331b68cf8e8646f09e6ddcad2d32d83", wantErr: false},
		{name: "env.php does not exist", envPath: "../dirdoesnotexist/env.php", key: "", wantErr: true},
		{name: "successfully extract latest key from valid env.php", envPath: "../sample/envsinglekey.php", key: "ccf8bfc4c5dce8b87f6d6f03c7c4612b", wantErr: false},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetLatestKey(tt.envPath)
			if (err != nil) && (tt.wantErr == false) {
				t.Errorf("Expected no error, instead got %v", err)
				return
			}

			if tt.key != key {
				t.Errorf("got key %s, want key %s", key, tt.key)
			}
		})
	}
}

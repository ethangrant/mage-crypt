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
	key     Key
	wantErr bool
}

func TestGetLatestKey(t *testing.T) {
	testCases := []GetLatestKeyTestCase{
		{name: "successfully extract latest key from valid env.php with multiple keys", envPath: "../sample/envmultiplekeys.php", key: Key{Value: "e331b68cf8e8646f09e6ddcad2d32d83", VersionId: 1}, wantErr: false},
		{name: "env.php does not exist", envPath: "../dirdoesnotexist/env.php", key: Key{"", 0}, wantErr: true},
		{name: "successfully extract latest key from valid env.php", envPath: "../sample/envsinglekey.php", key: Key{Value: "ccf8bfc4c5dce8b87f6d6f03c7c4612b", VersionId: 0}, wantErr: false},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetLatestKey(tt.envPath)
			if (err != nil) && (tt.wantErr == false) {
				t.Errorf("Expected no error, instead got %v", err)
				return
			}

			if tt.key.Value != key.Value {
				t.Errorf("got key %s, want key %s", key.Value, tt.key.Value)
			}

			if tt.key.VersionId != key.VersionId {
				t.Errorf("got version id %d, want version id %d", key.VersionId, tt.key.VersionId)
			}
		})
	}
}

type GetKeyByValueTestCase struct {
	name    string
	envPath string
	value   string
	key     Key
	wantErr bool
}

func TestGetKeyByValue(t *testing.T) {
	testCases := []GetKeyByValueTestCase{
		{name: "Expects first key to be returned", envPath: "../sample/envmultiplekeys.php", value: "0:3:DvbaN9LZ58qPYYiCMLPXkEHWpFz191qn:9lAAFFgTGtZ0N7AHWzqxb9hrdDnRvO15OsxZvHOiUa8=", key: Key{"ccf8bfc4c5dce8b87f6d6f03c7c4612b", 0}, wantErr: false},
		{name: "Expects second key to be returned", envPath: "../sample/envmultiplekeys.php", value: "1:3:DvbaN9LZ58qPYYiCMLPXkEHWpFz191qn:9lAAFFgTGtZ0N7AHWzqxb9hrdDnRvO15OsxZvHOiUa8=", key: Key{"e331b68cf8e8646f09e6ddcad2d32d83", 1}, wantErr: false},
		{name: "Expects first key to be returned single key env.php", envPath: "../sample/envsinglekey.php", value: "0:3:DvbaN9LZ58qPYYiCMLPXkEHWpFz191qn:9lAAFFgTGtZ0N7AHWzqxb9hrdDnRvO15OsxZvHOiUa8=", key: Key{"ccf8bfc4c5dce8b87f6d6f03c7c4612b", 0}, wantErr: false},
		{name: "Key does not exist with version provided", envPath: "../sample/envsinglekey.php", value: "4:3:DvbaN9LZ58qPYYiCMLPXkEHWpFz191qn:9lAAFFgTGtZ0N7AHWzqxb9hrdDnRvO15OsxZvHOiUa8=", key: Key{"", 0}, wantErr: true},
		{name: "Value provided does not have a valid part", envPath: "../sample/envsinglekey.php", value: "9lAAFFgTGtZ0N7AHWzqxb9hrdDnRvO15OsxZvHOiUa8=", key: Key{"", 0}, wantErr: true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetKeyByValue(tt.envPath, tt.value)

			if (err != nil) && (tt.wantErr == false) {
				t.Errorf("Expected no error, instead got %v", err)
				return
			}

			if (tt.wantErr == true) && (err == nil) {
				t.Errorf("Expected error, instead got %v", err)
				return
			}

			if err != nil {
				return
			}

			if tt.key.Value != key.Value {
				t.Errorf("got key %s, want key %s", key.Value, tt.key.Value)
			}

			if tt.key.VersionId != key.VersionId {
				t.Errorf("got version id %d, want version id %d", key.VersionId, tt.key.VersionId)
			}
		})
	}
}

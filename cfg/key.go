package cfg

import(
	"github.com/sansecio/gocommerce/phpcfg"
)

func GetCryptKeys(envPath string) ([]string, error) {
	var keys []string
	config, err := phpcfg.Parse([]byte(envPath))
	if err != nil {
		return nil, err
	}

	return keys, nil
}
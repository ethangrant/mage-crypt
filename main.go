package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/sansecio/gocommerce"
)

func main() {
	// TODO: accept path to env.php as an arg
	m2store := gocommerce.AllPlatforms[1]
	storeConfig, err := m2store.ParseConfig("/var/www/vanilla/web/app/etc/env.php")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(storeConfig)
}
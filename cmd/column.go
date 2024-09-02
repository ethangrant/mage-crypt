package cmd

import (
	"fmt"
	"github.com/ethangrant/mage-crypt/cfg"
	"github.com/ethangrant/mage-crypt/db"
	"github.com/ethangrant/mage-crypt/encryptor"
	"github.com/spf13/cobra"
	"os"
)

// encryptColumnCmd represents the encryptColumn command
var encryptColumnCmd = &cobra.Command{
	Use:   "encrypt:column",
	Short: "Re-encrypt `core_config_data.value` using the latest encryption key.",

	Run: func(cmd *cobra.Command, args []string) {
		envPath, err := cmd.Flags().GetString("env")
		if err != nil {
			fmt.Println("There was an error parsing command flag 'env': ", err.Error())
			return
		}

		dryRun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			fmt.Println("There was an error parsing command flag 'dry-run': ", err.Error())
			return
		}

		// check env file exists
		_, err = os.Stat(envPath)
		if err != nil {
			fmt.Printf("'%s' could not be found is the path correct?\n", envPath)
			return
		}

		// get db connection
		db, err := db.Connect(envPath)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		// encrypt using the most recent crypt key
		latestKey, err := cfg.GetLatestKey(envPath)
		if err != nil {
			fmt.Println("Failed to extract keys from env.php: ", err.Error())
		}

		err = encryptor.Column(db, latestKey, envPath, dryRun)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptColumnCmd)

	encryptColumnCmd.Flags().StringP("env", "e", "app/etc/env.php", "Provide absolute or relative path to env.php")
	encryptColumnCmd.Flags().StringP("table", "t", "", "Table that contains encrypted values")
	encryptColumnCmd.Flags().StringP("column", "c", "", "Column name that contains encrypted values")

	encryptColumnCmd.Flags().BoolP("dry-run", "d", true, "Dry-run will not perform any data updates, this flag defaults to true. Pass flag --dry-run=false to perform data updates. You should review dry-run output before doing this.")

	encryptColumnCmd.MarkFlagRequired("env")
	encryptColumnCmd.MarkFlagRequired("table")
	encryptColumnCmd.MarkFlagRequired("column")
}

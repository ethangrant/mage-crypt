/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"github.com/ethangrant/mage-crypt/encryptor"
	"github.com/spf13/cobra"
)

// encryptConfigCmd represents the encryptConfig command
var encryptConfigCmd = &cobra.Command{
	Use:   "encrypt:config",
	Short: "Re-encrypt core_config_data.value using the latest encryption key.",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("encryptConfig called")
		encryptor.CoreConfigData()
	},
}

func init() {
	rootCmd.AddCommand(encryptConfigCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptConfigCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptConfigCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

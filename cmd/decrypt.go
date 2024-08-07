package cmd

import (
	"fmt"

	"github.com/ethangrant/mage-crypt/cipher"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt Magento 2 encrypted value",
	Run: func(cmd *cobra.Command, args []string) {
		ciphertext, err := cmd.Flags().GetString("ciphertext")
		if err != nil {
			fmt.Printf("Failed to parse ciphertext param \n")
			return
		}

		key, err := cmd.Flags().GetString("key")
		if err != nil {
			fmt.Printf("Failed to parse key param \n")
			return
		}

		crypt, err := cipher.GetCipherByValue(ciphertext)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		plaintext, err := crypt.Decrypt(ciphertext, key)
		if err != nil {
			fmt.Printf("Failed to decrypt value %s: %s \n", ciphertext, err.Error())
			return
		}

		fmt.Println("ciphertext: ", ciphertext)
		fmt.Println("plaintext: ", plaintext)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("ciphertext", "c", "", "Encrypted value from Magento 2")
	decryptCmd.Flags().StringP("key", "k", "", "Key used to decrypt the encrypted value")

	decryptCmd.MarkFlagRequired("ciphertext")
	decryptCmd.MarkFlagRequired("key")
}

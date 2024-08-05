package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mage-crypt",
	Short: "Magento 2 Encryption Manager",
	Long: ` _____ ______   ________  ________  _______                  ________  ________      ___    ___ ________  _________   
|\   _ \  _   \|\   __  \|\   ____\|\  ___ \                |\   ____\|\   __  \    |\  \  /  /|\   __  \|\___   ___\ 
\ \  \\\__\ \  \ \  \|\  \ \  \___|\ \   __/|   ____________\ \  \___|\ \  \|\  \   \ \  \/  / | \  \|\  \|___ \  \_| 
 \ \  \\|__| \  \ \   __  \ \  \  __\ \  \_|/__|\____________\ \  \    \ \   _  _\   \ \    / / \ \   ____\   \ \  \  
  \ \  \    \ \  \ \  \ \  \ \  \|\  \ \  \_|\ \|____________|\ \  \____\ \  \\  \|   \/  /  /   \ \  \___|    \ \  \ 
   \ \__\    \ \__\ \__\ \__\ \_______\ \_______\              \ \_______\ \__\\ _\ __/  / /      \ \__\        \ \__\
    \|__|     \|__|\|__|\|__|\|_______|\|_______|               \|_______|\|__|\|__|\___/ /        \|__|         \|__|`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.mage-crypt.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}



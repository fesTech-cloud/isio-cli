package cmd

import (
	"fmt"
	"isio/helper"

	"github.com/spf13/cobra"
)

// defaultCmd represents the default command
var defaultCmd = &cobra.Command{
	Use:   "default",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if the --golang flag was passed
		golangFlag, _ := cmd.Flags().GetBool("golang")
		if golangFlag {
			// Call the CreateGolangFolder function
			if len(args) < 0 {
				fmt.Println("Provide the package name")
				return
			}
			helper.CreateGolangFolder(args[0])
		} else {
			fmt.Println("No action taken. Use --golang flag to create the Golang folder.")
		}
	},
}

func init() {
	rootCmd.AddCommand(defaultCmd)

	// Define the --golang flag
	defaultCmd.Flags().BoolP("golang", "g", false, "Create a Golang folder")
}

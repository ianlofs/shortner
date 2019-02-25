// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const appName = "shortner"

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   appName,
	Short: "Shorten URLs",
	Long: `A webserver that shortens URLs and redirects
	shortned urls to their ultimate destinations.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func setupLogging(level string, jsonFormat bool) {
	switch level {
	case "TRACE":
		log.SetLevel(log.TraceLevel)
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
	case "FATAL":
		log.SetLevel(log.FatalLevel)
	case "PANIC":
		log.SetLevel(log.PanicLevel)
	default:
		log.Panic("You must set a log level")
	}

	if jsonFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}

}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./.shortner.yaml)")

	rootCmd.Flags().StringP("log-level", "l", "DEBUG", "Set the log level of the application.")
	rootCmd.Flags().Bool("json-format", false, "Whether or not to json format the logs. Defaults to false.")
	rootCmd.Flags().StringP("mysql-user", "u", "", "MySQL user to access the db instance with.")
	rootCmd.Flags().StringP("mysql-password", "p", "", "MySQL password to access the db instance with.")
	rootCmd.Flags().StringP("mysql-host", "H", "127.0.0.1", "MySQL host to access the db instance with.")
	rootCmd.Flags().IntP("mysql-port", "P", 3306, "MySQL port to access the db instance with.")
	rootCmd.Flags().StringP("mysql-database", "d", appName, "MySQL database to access the db instance with.")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	fmt.Println("Initing!!!")
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config file in current directory.
		viper.SetConfigFile("." + appName + ".yaml")
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Printf("Using configfile at %s", viper.ConfigFileUsed())
	}

	dashToUs := strings.NewReplacer("-", "_")
	viper.SetEnvPrefix(strings.ToUpper(appName))
	viper.SetEnvKeyReplacer(dashToUs)

	viper.AutomaticEnv() // read in environment variables that match

	// Bind all cobra command flags to viper.
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		viper.BindPFlag(f.Name, f)
	})

	setupLogging(viper.GetString("log-level"), viper.GetBool("json-format"))
}

func buildServerConfig() (shortner.Config, error) {
	mysqlUser := viper.GetString("mysql-user")
	mysqlPassword := viper.GetString("mysql-password")
	mysqlHost := viper.GetString("mysql-host")
	mysqlPort := viper.GetString("mysql-port")
	mysqlDatabase := viper.GetString("mysql-database")
}

func runServer(cmd *cobra.Command, _ []string) error {

	cfg, err := shortner.NewServer()
}

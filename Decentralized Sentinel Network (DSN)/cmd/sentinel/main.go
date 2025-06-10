package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dsn/decentralized-sentinel-network/internal/sentinel"
	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var cfgFile string

	rootCmd := &cobra.Command{
		Use:   "sentinel",
		Short: "DSN Sentinel Node - Security monitoring and threat detection",
		Long: `DSN Sentinel Node provides real-time security monitoring, threat detection,
and configuration validation for the Decentralized Sentinel Network.

The sentinel node monitors system health, detects security threats, validates
configurations, and coordinates with other DSN components to maintain security.`,
		RunE: runSentinel,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.dsn/sentinel.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, text)")
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug mode")

	// Bind flags to viper
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))

	// Add subcommands
	rootCmd.AddCommand(newVersionCommand())
	rootCmd.AddCommand(newHealthCheckCommand())
	rootCmd.AddCommand(newConfigCommand())

	// Initialize configuration
	cobra.OnInitialize(func() {
		initConfig(cfgFile)
	})

	return rootCmd
}

func runSentinel(cmd *cobra.Command, args []string) error {
	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:  viper.GetString("log.level"),
		Format: viper.GetString("log.format"),
		Debug:  viper.GetBool("debug"),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	log.Info("Starting DSN Sentinel Node",
		"version", version,
		"commit", commit,
		"buildTime", buildTime,
	)

	// Load configuration
	cfg, err := config.LoadSentinelConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	log.Info("Configuration loaded successfully",
		"sentinelId", cfg.SentinelID,
		"grpcPort", cfg.Server.GRPCPort,
		"httpPort", cfg.Server.HTTPPort,
	)

	// Create sentinel instance
	sentinelNode, err := sentinel.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create sentinel node: %w", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info("Received shutdown signal", "signal", sig)
		cancel()
	}()

	// Start sentinel node
	log.Info("Starting sentinel node services...")
	if err := sentinelNode.Start(ctx); err != nil {
		return fmt.Errorf("failed to start sentinel node: %w", err)
	}

	// Wait for shutdown
	<-ctx.Done()
	log.Info("Shutting down sentinel node...")

	// Graceful shutdown
	if err := sentinelNode.Stop(); err != nil {
		log.Error("Error during shutdown", "error", err)
		return err
	}

	log.Info("Sentinel node stopped successfully")
	return nil
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("DSN Sentinel Node\n")
			fmt.Printf("Version:    %s\n", version)
			fmt.Printf("Commit:     %s\n", commit)
			fmt.Printf("Build Time: %s\n", buildTime)
		},
	}
}

func newHealthCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Perform health check",
		RunE: func(cmd *cobra.Command, args []string) error {
			// This is used by Docker/Kubernetes health checks
			cfg, err := config.LoadSentinelConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			client, err := sentinel.NewHealthClient(cfg.Server.GRPCPort)
			if err != nil {
				return fmt.Errorf("failed to create health client: %w", err)
			}
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), cfg.HealthCheck.Timeout)
			defer cancel()

			if err := client.Check(ctx); err != nil {
				return fmt.Errorf("health check failed: %w", err)
			}

			fmt.Println("Health check passed")
			return nil
		},
	}
}

func newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
	}

	configCmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadSentinelConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("configuration validation failed: %w", err)
			}

			fmt.Println("Configuration is valid")
			return nil
		},
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadSentinelConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Print configuration (sanitized)
			fmt.Printf("Sentinel Configuration:\n")
			fmt.Printf("  ID: %s\n", cfg.SentinelID)
			fmt.Printf("  gRPC Port: %d\n", cfg.Server.GRPCPort)
			fmt.Printf("  HTTP Port: %d\n", cfg.Server.HTTPPort)
			fmt.Printf("  Log Level: %s\n", cfg.Logging.Level)
			fmt.Printf("  Metrics Enabled: %t\n", cfg.Metrics.Enabled)
			fmt.Printf("  Health Check Interval: %s\n", cfg.HealthCheck.Interval)

			return nil
		},
	})

	return configCmd
}

func initConfig(cfgFile string) {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".dsn" (without extension)
		viper.AddConfigPath(home + "/.dsn")
		viper.AddConfigPath("/etc/dsn")
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("sentinel")
	}

	// Environment variables
	viper.SetEnvPrefix("DSN")
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.grpc_port", 9090)
	viper.SetDefault("server.http_port", 8080)
	viper.SetDefault("server.metrics_port", 8081)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")

	// Logging defaults
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.path", "/metrics")

	// Health check defaults
	viper.SetDefault("health_check.enabled", true)
	viper.SetDefault("health_check.interval", "30s")
	viper.SetDefault("health_check.timeout", "5s")

	// Threat detection defaults
	viper.SetDefault("threat_detection.enabled", true)
	viper.SetDefault("threat_detection.scan_interval", "60s")
	viper.SetDefault("threat_detection.deep_scan_enabled", false)

	// Security defaults
	viper.SetDefault("security.tls.enabled", true)
	viper.SetDefault("security.mtls.enabled", false)
	viper.SetDefault("security.vault.enabled", false)
}
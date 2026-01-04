package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hnakamur/ghesmanage"
)

func main() {
	domain := flag.String("domain", "", "domain of GitHub Enterprise Server")
	flag.Parse()

	user := os.Getenv("API_USER")
	password := os.Getenv("API_PASSWORD")
	if user == "" || password == "" {
		log.Fatal("please set API_USER and API_PASSWORD environment variables")
	}
	if err := run(*domain, user, password); err != nil {
		log.Fatal(err)
	}
}

func run(domain, user, passwd string) error {
	if err := setupSlogDefaultLogger(os.Stderr, "debug"); err != nil {
		return err
	}

	cfg := &GHESManageConfig{
		ApplyWaitInitialDelay: 10 * time.Second,
		ApplyWaitInterval:     30 * time.Second,
		HTTPClient: GHESManageHTTPClientConfig{
			Timeout:       30 * time.Second,
			TLSSkipVerify: true,
		},
		HTTPAuth: GHESManageHTTPAuthConfig{
			User:     user,
			Password: passwd,
		},
	}
	return applyConfigAndWait(context.Background(), domain, cfg)
}

type GHESManageConfig struct {
	ApplyWaitInitialDelay time.Duration              `yaml:"apply_wait_initial_delay"`
	ApplyWaitInterval     time.Duration              `yaml:"apply_wait_interval"`
	HTTPClient            GHESManageHTTPClientConfig `yaml:"http_client"`
	HTTPAuth              GHESManageHTTPAuthConfig   `yaml:"http_auth"`
}

type GHESManageHTTPClientConfig struct {
	Timeout       time.Duration `yaml:"timeout"`
	TLSSkipVerify bool          `yaml:"tls_skip_verify"`
}

type GHESManageHTTPAuthConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

const (
	managementEndpointScheme = "https"
	managementEndpointPort   = "8443"
	managementEndpointPath   = "/manage"
)

func applyConfigAndWait(ctx context.Context, domain string, cfg *GHESManageConfig) error {
	httpClient := &http.Client{Timeout: cfg.HTTPClient.Timeout}
	if cfg.HTTPClient.TLSSkipVerify {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig.InsecureSkipVerify = true
		httpClient.Transport = tr
		slog.Debug("enabled httpClient TLSClientConfig.InsecureSkipVerify")
	}

	managementEndpoint := (&url.URL{
		Scheme: managementEndpointScheme,
		Host:   net.JoinHostPort(domain, managementEndpointPort),
		Path:   managementEndpointPath,
	}).String()

	apiClient, err := ghesmanage.NewAPIClient(httpClient, managementEndpoint, cfg.HTTPAuth.User, cfg.HTTPAuth.Password)
	if err != nil {
		return err
	}

	startTime := time.Now()
	runID, err := apiClient.TriggerConfigApply(ctx)
	if err != nil {
		return err
	}
	slog.Info("triggered config apply", "run_id", runID)

	slog.Debug("polling config to be applied...",
		"initial_delay", cfg.ApplyWaitInitialDelay.String(),
		"interval", cfg.ApplyWaitInterval.String())

	select {
	case <-ctx.Done():
		return nil
	case <-time.After(cfg.ApplyWaitInitialDelay):
	}

	for {
		status, err := apiClient.GetConfigApplyStatus(ctx, runID)
		if err != nil {
			return err
		}
		slog.Info("got config apply status",
			"status", status)

		if !status.Running {
			if !status.Successful {
				return errors.New("failed to apply config")
			}
			slog.Info("config apply finished", "elapsed", time.Since(startTime).String())
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cfg.ApplyWaitInterval):
		}
	}
}

func setupSlogDefaultLogger(w io.Writer, level string) error {
	lvl, err := parseSlogLogLevel(level)
	if err != nil {
		return err
	}
	var programLevel = new(slog.LevelVar)
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: programLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			_ = groups
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					// format timestamp with millisecond precision
					a.Value = slog.StringValue(t.Format("2006-01-02T15:04:05.000000"))
				}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
	programLevel.Set(lvl)
	return nil
}

func parseSlogLogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.Level(math.MinInt),
			fmt.Errorf("unsupported slog level: %s", level)
	}
}

package server

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestRefusesToStartWithoutAMerchantSecret(t *testing.T) {
	dir := t.TempDir()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := Run(context.Background(), Config{DataDir: dir, CertDir: dir, Logger: quiet})
	if err == nil || !strings.Contains(err.Error(), "PSTCO_MERCHANT_SECRET") {
		t.Fatalf("started with no secret: %v", err)
	}
	err = Run(context.Background(), Config{DataDir: dir, CertDir: dir, MerchantSecret: "short", Logger: quiet})
	if err == nil || !strings.Contains(err.Error(), "16 characters") {
		t.Fatalf("started with a weak secret: %v", err)
	}
}

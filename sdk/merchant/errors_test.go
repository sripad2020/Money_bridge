package merchant

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/status"
)

func TestInternalErrorsDoNotLeakDetails(t *testing.T) {
	err := toStatus(errors.New("sqlite: C:\\data\\pstco.db: disk I/O error"))
	if s, _ := status.FromError(err); strings.Contains(s.Message(), "pstco.db") || s.Message() != "internal error" {
		t.Fatalf("internal detail leaked: %q", s.Message())
	}
}

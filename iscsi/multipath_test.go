package iscsi

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/prashantv/gostub"
	"github.com/stretchr/testify/assert"
)

func TestExecWithTimeout(t *testing.T) {
	tests := map[string]struct {
		wantOutput  string
		wantErr     bool
		wantTimeout bool
		stubCmd     func(ctx context.Context, command string, args ...string) *exec.Cmd
	}{
		"Success": {
			wantOutput: "some output",
			stubCmd: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
				return exec.CommandContext(ctx, "echo", "-n", "some output")
			},
		},
		"WithError": {
			wantErr: true,
			stubCmd: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
				return exec.CommandContext(ctx, "false")
			},
		},
		"WithTimeout": {
			wantTimeout: true,
			stubCmd: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
				// "sleep 999" will block until the context deadline kills it
				return exec.CommandContext(ctx, "sleep", "999")
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			timeout := 5 * time.Second
			if tt.wantTimeout {
				timeout = 50 * time.Millisecond
			}

			defer gostub.Stub(&execCommandContext, tt.stubCmd).Reset()

			out, err := ExecWithTimeout("dummy", []string{}, timeout)

			if tt.wantTimeout {
				assert.ErrorIs(err, context.DeadlineExceeded)
				assert.Empty(out)
			} else if tt.wantErr {
				assert.NotNil(err)
			} else {
				assert.Nil(err)
				assert.Equal(tt.wantOutput, string(out))
			}
		})
	}
}

package iscsi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// ExecWithTimeout execute a command with a timeout and returns an error if timeout is exceeded
func ExecWithTimeout(ctx context.Context, command string, args []string, timeout time.Duration) ([]byte, error) {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Executing command with timeout", "command", command, "args", args, "timeout", timeout)

	// Create a new context and add a timeout to it
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create command with context
	cmd := execCommandContext(ctx, command, args...)

	// This time we can simply use Output() to get the result.
	out, err := cmd.Output()
	if err != nil {
		logger.Error(err, "Command error", "command", command, "timeout", timeout, "output", out)
	}

	// We want to check the context error to see if the timeout was executed.
	// The error returned by cmd.Output() will be OS specific based on what
	// happens when a process is killed.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		logger.V(1).Info("Command timeout reached", "command", command, "timeout", timeout)
		return nil, ctx.Err()
	}

	if err != nil {
		var ee *exec.ExitError
		if ok := errors.Is(err, ee); ok {
			logger.Error(err, "Non-zero exit code", "command", command)
			err = fmt.Errorf("%s", ee.Stderr)
		}
	}

	return out, err
}

// FlushMultipathDevice flushes a multipath device dm-x with command multipath -f /dev/dm-x
func FlushMultipathDevice(ctx context.Context, device *Device) error {
	devicePath := device.GetPath()
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Flushing multipath device", "device", devicePath)

	timeout := 5 * time.Second
	_, err := execWithTimeout(ctx, "multipath", []string{"-f", devicePath}, timeout)

	if err != nil {
		if _, e := osStat(devicePath); os.IsNotExist(e) {
			logger.V(1).Info("Multipath device has been removed", "device", devicePath)
		} else {
			if strings.Contains(err.Error(), "map in use") {
				err = fmt.Errorf("device is probably still in use somewhere else: %v", err)
			}
			logger.Error(err, "Command 'multipath -f <device>' did not succeed to delete the device", "device", devicePath)
			return err
		}
	}

	logger.V(1).Info("Finished flushing multipath device", "device", devicePath)
	return nil
}

// ResizeMultipathDevice resize a multipath device based on its underlying devices
func ResizeMultipathDevice(ctx context.Context, device *Device) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Resizing multipath device", "device", device.GetPath())

	if output, err := execCommand("multipathd", "resize", "map", device.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("could not resize multipath device: %s (%v)", output, err)
	}

	return nil
}

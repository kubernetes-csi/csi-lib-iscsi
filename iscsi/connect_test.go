package iscsi

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/prashantv/gostub"
)

func TestConnectReturnsMountTargetErrorAfterCleanup(t *testing.T) {
	const iqn = "iqn.2026-10.example:volume"
	devices := deviceInfo{
		{Name: "sda", Hctl: "0:0:0:1", Type: "disk", Transport: "iscsi", Size: "1G"},
		{Name: "sdb", Hctl: "1:0:0:1", Type: "disk", Transport: "iscsi", Size: "1G"},
	}
	cleanupFailure := errors.New("fake cleanup failure")
	for _, test := range []struct {
		name       string
		cleanupErr error
	}{
		{name: "successful cleanup"},
		{name: "failed cleanup", cleanupErr: cleanupFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubs := gostub.Stub(&execWithTimeout, func(command string, args []string, _ time.Duration) ([]byte, error) {
				if command != "iscsiadm" {
					t.Fatalf("unexpected command: %s", command)
				}
				if len(args) >= 2 && args[1] == "iface" {
					return []byte("iface.transport_name = tcp\n"), nil
				}
				if len(args) >= 2 && args[1] == "session" {
					return []byte(fmt.Sprintf("tcp: [1] 192.0.2.1:3260,1 %s\ntcp: [2] 192.0.2.2:3260,1 %s\n", iqn, iqn)), nil
				}
				return nil, nil
			})
			defer stubs.Reset()
			stubs.Stub(&osStat, func(path string) (os.FileInfo, error) {
				if path != "/dev/sda" && path != "/dev/sdb" && !strings.HasPrefix(path, "/dev/disk/by-path/") {
					t.Fatalf("unexpected device path: %s", path)
				}
				return nil, nil
			})
			stubs.Stub(&execCommand, func(command string, args ...string) *exec.Cmd {
				switch command {
				case "lsblk":
					return makeFakeExecCommand(0, marshalDeviceInfo(&devices))(command, args...)
				case "blockdev":
					return makeFakeExecCommand(0, "")(command, args...)
				default:
					t.Fatalf("unexpected command: %s", command)
					return nil
				}
			})
			var cleanedFiles []string
			stubs.Stub(&osOpenFile, func(path string, _ int, _ os.FileMode) (*os.File, error) {
				if !strings.HasPrefix(path, "/sys/class/scsi_device/") {
					t.Fatalf("unexpected cleanup path: %s", path)
				}
				if test.cleanupErr != nil {
					return nil, test.cleanupErr
				}
				cleanedFiles = append(cleanedFiles, path)
				return os.CreateTemp(t.TempDir(), "device-")
			})

			connector := Connector{TargetIqn: iqn, TargetPortals: []string{"192.0.2.1", "192.0.2.2"}}
			path, err := connector.Connect()
			if path != "" {
				t.Errorf("Connect() path = %q, want empty", path)
			}
			if test.cleanupErr != nil {
				if !errors.Is(err, cleanupFailure) {
					t.Errorf("Connect() error = %v, want cleanup failure", err)
				}
				return
			}
			if len(cleanedFiles) != 4 {
				t.Errorf("cleanup wrote %d device files, want 4", len(cleanedFiles))
			}
			if err == nil || !strings.Contains(err.Error(), "device is not mapped to exactly one multipath device") {
				t.Errorf("Connect() error = %v, want mount target selection failure", err)
			}
			if connector.MountTargetDevice != nil || len(connector.Devices) != 0 {
				t.Errorf("Connect() retained device state after successful cleanup: %+v", connector)
			}
		})
	}
}

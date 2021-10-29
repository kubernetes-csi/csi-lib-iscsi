package iscsi

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prashantv/gostub"
	"github.com/stretchr/testify/assert"
)

type testWriter struct {
	data *[]byte
}

func (w testWriter) Write(data []byte) (n int, err error) {
	*w.data = append(*w.data, data...)
	return len(data), nil
}

const nodeDB = `
# BEGIN RECORD 6.2.0.874
node.name = iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced
node.tpgt = -1
node.startup = automatic
node.leading_login = No
iface.iscsi_ifacename = default
iface.transport_name = tcp
iface.vlan_id = 0
iface.vlan_priority = 0
iface.iface_num = 0
iface.mtu = 0
iface.port = 0
iface.tos = 0
iface.ttl = 0
iface.tcp_wsf = 0
iface.tcp_timer_scale = 0
iface.def_task_mgmt_timeout = 0
iface.erl = 0
iface.max_receive_data_len = 0
iface.first_burst_len = 0
iface.max_outstanding_r2t = 0
iface.max_burst_len = 0
node.discovery_port = 0
node.discovery_type = static
node.session.initial_cmdsn = 0
node.session.initial_login_retry_max = 8
node.session.xmit_thread_priority = -20
node.session.cmds_max = 128
node.session.queue_depth = 32
node.session.nr_sessions = 1
node.session.auth.authmethod = CHAP
node.session.auth.username = 86Jx6hXYqDYpKamtgx4d
node.session.auth.password = Qj3MuzmHu8cJBpkv
node.session.timeo.replacement_timeout = 120
node.session.err_timeo.abort_timeout = 15
node.session.err_timeo.lu_reset_timeout = 30
node.session.err_timeo.tgt_reset_timeout = 30
node.session.err_timeo.host_reset_timeout = 60
node.session.iscsi.FastAbort = Yes
node.session.iscsi.InitialR2T = No
node.session.iscsi.ImmediateData = Yes
node.session.iscsi.FirstBurstLength = 262144
node.session.iscsi.MaxBurstLength = 16776192
node.session.iscsi.DefaultTime2Retain = 0
node.session.iscsi.DefaultTime2Wait = 2
node.session.iscsi.MaxConnections = 1
node.session.iscsi.MaxOutstandingR2T = 1
node.session.iscsi.ERL = 0
node.conn[0].address = 192.168.1.107
node.conn[0].port = 3260
node.conn[0].startup = manual
node.conn[0].tcp.window_size = 524288
node.conn[0].tcp.type_of_service = 0
node.conn[0].timeo.logout_timeout = 15
node.conn[0].timeo.login_timeout = 15
node.conn[0].timeo.auth_timeout = 45
node.conn[0].timeo.noop_out_interval = 5
node.conn[0].timeo.noop_out_timeout = 5
node.conn[0].iscsi.MaxXmitDataSegmentLength = 0
node.conn[0].iscsi.MaxRecvDataSegmentLength = 262144
node.conn[0].iscsi.HeaderDigest = None
node.conn[0].iscsi.IFMarker = No
node.conn[0].iscsi.OFMarker = No
# END RECORD
`

const emptyTransportName = "iface.transport_name = \n"
const emptyDbRecord = "\n\n\n"
const testRootFS = "/tmp/iscsi-tests"

func makeFakeExecCommand(exitStatus int, stdout string) func(string, ...string) *exec.Cmd {
	return func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestExecCommandHelper", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		es := strconv.Itoa(exitStatus)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1",
			"STDOUT=" + stdout,
			"EXIT_STATUS=" + es}
		return cmd
	}
}

func makeFakeExecCommandContext(exitStatus int, stdout string) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, command string, args ...string) *exec.Cmd {
		return makeFakeExecCommand(exitStatus, stdout)(command, args...)
	}
}

func makeFakeExecWithTimeout(testCmdTimeout bool, testExecWithTimeoutError error) func(string, []string, time.Duration) ([]byte, error) {
	return func(command string, args []string, timeout time.Duration) ([]byte, error) {
		if testCmdTimeout {
			return nil, context.DeadlineExceeded
		}
		return []byte(""), testExecWithTimeoutError
	}
}

func TestExecCommandHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	fmt.Fprintf(os.Stdout, os.Getenv("STDOUT"))
	i, _ := strconv.Atoi(os.Getenv("EXIT_STATUS"))
	os.Exit(i)
}

func getDevicePath(device *Device) string {
	sysDevicePath := "/tmp/iscsi-tests/sys/class/scsi_device/"
	return filepath.Join(sysDevicePath, device.Hctl, "device")
}

func preparePaths(devices []Device) error {
	for _, d := range devices {
		devicePath := getDevicePath(&d)

		if err := os.MkdirAll(devicePath, os.ModePerm); err != nil {
			return err
		}

		for _, filename := range []string{"delete", "state"} {
			if err := ioutil.WriteFile(filepath.Join(devicePath, filename), []byte(""), 0600); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkFileContents(t *testing.T, path string, contents string) {
	if out, err := ioutil.ReadFile(path); err != nil {
		t.Errorf("could not read file: %v", err)
		return
	} else if string(out) != contents {
		t.Errorf("file content mismatch, got = %q, want = %q", string(out), contents)
		return
	}
}

func Test_parseSessions(t *testing.T) {
	var sessions []iscsiSession
	output := "tcp: [2] 192.168.1.107:3260,1 iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced (non-flash)\n" +
		"tcp: [2] 192.168.1.200:3260,1 iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced (non-flash)\n"

	sessions = append(sessions,
		iscsiSession{
			Protocol: "tcp",
			ID:       2,
			Portal:   "192.168.1.107:3260",
			IQN:      "iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced",
			Name:     "volume-eb393993-73d0-4e39-9ef4-b5841e244ced",
		})
	sessions = append(sessions,
		iscsiSession{
			Protocol: "tcp",
			ID:       2,
			Portal:   "192.168.1.200:3260",
			IQN:      "iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced",
			Name:     "volume-eb393993-73d0-4e39-9ef4-b5841e244ced",
		})

	type args struct {
		lines string
	}
	validSession := args{
		lines: output,
	}
	tests := []struct {
		name string
		args args
		want []iscsiSession
	}{
		{"ValidParseSession", validSession, sessions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSessions(tt.args.lines)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSessions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extractTransportName(t *testing.T) {
	type args struct {
		output string
	}
	validRecord := args{
		output: nodeDB,
	}
	emptyRecord := args{
		output: emptyDbRecord,
	}
	emptyTransportRecord := args{
		output: emptyTransportName,
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"tcp-check", validRecord, "tcp"},
		{"tcp-check", emptyRecord, ""},
		{"tcp-check", emptyTransportRecord, "tcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTransportName(tt.args.output); got != tt.want {
				t.Errorf("extractTransportName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_sessionExists(t *testing.T) {
	fakeOutput := "tcp: [4] 192.168.1.107:3260,1 iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced (non-flash)\n"
	defer gostub.Stub(&execCommand, makeFakeExecCommand(0, fakeOutput)).Reset()

	type args struct {
		tgtPortal string
		tgtIQN    string
	}
	testExistsArgs := args{
		tgtPortal: "192.168.1.107:3260",
		tgtIQN:    "iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced",
	}
	testWrongPortalArgs := args{
		tgtPortal: "10.0.0.1:3260",
		tgtIQN:    "iqn.2010-10.org.openstack:volume-eb393993-73d0-4e39-9ef4-b5841e244ced",
	}

	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"TestSessionExists", testExistsArgs, true, false},
		{"TestSessionDoesNotExist", testWrongPortalArgs, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sessionExists(tt.args.tgtPortal, tt.args.tgtIQN)
			if (err != nil) != tt.wantErr {
				t.Errorf("sessionExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sessionExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_DisconnectNormalVolume(t *testing.T) {
	deleteDeviceFile := "/tmp/deleteDevice"
	defer gostub.Stub(&osOpenFile, func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return os.OpenFile(deleteDeviceFile, flag, perm)
	}).Reset()

	tests := []struct {
		name           string
		withDeviceFile bool
		wantErr        bool
	}{
		{"DisconnectNormalVolume", true, false},
		{"DisconnectNonexistentNormalVolume", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.withDeviceFile {
				os.Create(deleteDeviceFile)
			} else {
				os.RemoveAll(testRootFS)
			}

			device := Device{Name: "test"}
			c := Connector{Devices: []Device{device}, MountTargetDevice: &device}
			err := c.DisconnectVolume()
			if (err != nil) != tt.wantErr {
				t.Errorf("DisconnectVolume() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.withDeviceFile {
				out, err := ioutil.ReadFile(deleteDeviceFile)
				if err != nil {
					t.Errorf("can not read file %v: %v", deleteDeviceFile, err)
					return
				}
				if string(out) != "1" {
					t.Errorf("file content mismatch, got = %s, want = 1", string(out))
					return
				}
			}
		})
	}
}

func Test_DisconnectMultipathVolume(t *testing.T) {
	defer gostub.Stub(&execCommand, makeFakeExecCommand(0, "")).Reset()
	defer gostub.Stub(&osStat, func(name string) (os.FileInfo, error) {
		return nil, nil
	}).Reset()

	tests := []struct {
		name           string
		timeout        bool
		withDeviceFile bool
		wantErr        bool
		cmdError       error
	}{
		{"DisconnectMultipathVolume", false, true, false, nil},
		{"DisconnectMultipathVolumeFlushTimeout", true, true, true, nil},
		{"DisconnectNonexistentMultipathVolume", false, false, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer gostub.Stub(&execWithTimeout, makeFakeExecWithTimeout(tt.timeout, tt.cmdError)).Reset()
			c := Connector{
				Devices:           []Device{{Hctl: "hctl1"}, {Hctl: "hctl2"}},
				MountTargetDevice: &Device{Type: "mpath"},
			}

			defer gostub.Stub(&osOpenFile, func(name string, flag int, perm os.FileMode) (*os.File, error) {
				return os.OpenFile(testRootFS+name, flag, perm)
			}).Reset()

			if tt.withDeviceFile {
				if err := preparePaths(c.Devices); err != nil {
					t.Errorf("could not prepare paths: %v", err)
					return
				}
			} else {
				os.Remove(testRootFS)
			}

			err := c.DisconnectVolume()
			if (err != nil) != tt.wantErr {
				t.Errorf("DisconnectVolume() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.timeout {
				if err != context.DeadlineExceeded {
					t.Errorf("DisconnectVolume() error = %v, wantErr %v", err, context.DeadlineExceeded)
					return
				}
			}

			if tt.withDeviceFile && !tt.wantErr {
				for _, device := range c.Devices {
					checkFileContents(t, getDevicePath(&device)+"/delete", "1")
					checkFileContents(t, getDevicePath(&device)+"/state", "offline\n")
				}
			}
		})
	}
}

func Test_EnableDebugLogging(t *testing.T) {
	assert := assert.New(t)
	data := []byte{}
	writer := testWriter{data: &data}
	EnableDebugLogging(writer)

	assert.Equal("", string(data))
	assert.Len(strings.Split(string(data), "\n"), 1)

	debug.Print("testing debug logs")
	assert.Contains(string(data), "testing debug logs")
	assert.Len(strings.Split(string(data), "\n"), 2)
}

func Test_waitForPathToExist(t *testing.T) {
	tests := map[string]struct {
		attempts     int
		fileNotFound bool
		withErr      bool
		transport    string
	}{
		"Basic": {
			attempts: 1,
		},
		"WithRetry": {
			attempts: 2,
		},
		"WithRetryFail": {
			attempts:     3,
			fileNotFound: true,
		},
		"WithError": {
			withErr: true,
		},
	}

	for name, tt := range tests {
		tt.transport = "tcp"
		tests[name+"OverTCP"] = tt
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			attempts := 0
			maxRetries := tt.attempts - 1
			if tt.fileNotFound {
				maxRetries--
			}
			if maxRetries < 0 {
				maxRetries = 0
			}
			doAttempt := func(err error) error {
				attempts++
				if tt.withErr {
					return err
				}
				if attempts < tt.attempts {
					return os.ErrNotExist
				}
				return nil
			}
			defer gostub.Stub(&osStat, func(name string) (os.FileInfo, error) {
				if err := doAttempt(os.ErrPermission); err != nil {
					return nil, err
				}
				return nil, nil
			}).Reset()
			defer gostub.Stub(&filepathGlob, func(name string) ([]string, error) {
				if err := doAttempt(filepath.ErrBadPattern); err != nil {
					return nil, err
				}
				return []string{"/somefilewithalongname"}, nil
			}).Reset()
			defer gostub.Stub(&sleep, func(_ time.Duration) {}).Reset()
			path := "/somefile"
			err := waitForPathToExist(&path, uint(maxRetries), 1, tt.transport)

			if tt.withErr {
				if tt.transport == "tcp" {
					assert.Equal(os.ErrPermission, err)
				} else {
					assert.Equal(filepath.ErrBadPattern, err)
				}
				return
			}
			if tt.fileNotFound {
				assert.Equal(os.ErrNotExist, err)
				assert.Equal(maxRetries, attempts-1)
			} else {
				assert.Nil(err)
				assert.Equal(tt.attempts, attempts)
				if tt.transport == "tcp" {
					assert.Equal("/somefile", path)
				} else {
					assert.Equal("/somefilewithalongname", path)
				}
			}
		})
	}

	t.Run("PathEmptyOrNil", func(t *testing.T) {
		assert := assert.New(t)
		path := ""

		err := waitForPathToExist(&path, 0, 0, "tcp")
		assert.NotNil(err)

		err = waitForPathToExist(&path, 0, 0, "")
		assert.NotNil(err)

		err = waitForPathToExist(nil, 0, 0, "tcp")
		assert.NotNil(err)

		err = waitForPathToExist(nil, 0, 0, "")
		assert.NotNil(err)
	})

	t.Run("PathNotFound", func(t *testing.T) {
		assert := assert.New(t)
		defer gostub.Stub(&filepathGlob, func(name string) ([]string, error) {
			return nil, nil
		}).Reset()

		path := "/test"
		err := waitForPathToExist(&path, 0, 0, "")
		assert.NotNil(err)
		assert.Equal(os.ErrNotExist, err)
	})
}

func Test_getMultipathDevice(t *testing.T) {
	mpath1 := Device{Name: "3600c0ff0000000000000000000000000", Type: "mpath"}
	mpath2 := Device{Name: "3600c0ff1111111111111111111111111", Type: "mpath"}
	sda := Device{Name: "sda", Children: []Device{{Name: "sda1"}}}
	sdb := Device{Name: "sdb", Children: []Device{mpath1}}
	sdc := Device{Name: "sdc", Children: []Device{mpath1}}
	sdd := Device{Name: "sdc", Children: []Device{mpath2}}
	sde := Device{Name: "sdc", Children: []Device{mpath1, mpath2}}

	tests := map[string]struct {
		mockedDevices    deviceInfo
		mockedStdout     string
		mockedExitStatus int
		multipathDevice  *Device
		wantErr          bool
	}{
		"Basic": {
			mockedDevices:   deviceInfo{BlockDevices: []Device{sdb, sdc}},
			multipathDevice: &mpath1,
		},
		"NotABlockDevice": {
			mockedStdout:     "lsblk: sdzz: not a block device",
			mockedExitStatus: 32,
		},
		"NotSharingTheSameMultipathDevice": {
			mockedDevices: deviceInfo{BlockDevices: []Device{sdb, sdd}},
			wantErr:       true,
		},
		"MoreThanOneMultipathDevice": {
			mockedDevices: deviceInfo{BlockDevices: []Device{sde}},
			wantErr:       true,
		},
		"NotAMultipathDevice": {
			mockedDevices: deviceInfo{BlockDevices: []Device{sda}},
			wantErr:       true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			mockedStdout := tt.mockedStdout
			if mockedStdout == "" {
				out, err := json.Marshal(tt.mockedDevices)
				assert.Nil(err, "could not setup test")
				mockedStdout = string(out)
			}

			gostub.Stub(&execCommand, makeFakeExecCommand(tt.mockedExitStatus, string(mockedStdout)))
			multipathDevice, err := getMultipathDevice(tt.mockedDevices.BlockDevices)

			if tt.mockedExitStatus != 0 || tt.wantErr {
				assert.Nil(multipathDevice)
				assert.NotNil(err)
			} else {
				assert.Equal(tt.multipathDevice, multipathDevice)
				assert.Nil(err)
			}
		})
	}
}

func Test_lsblk(t *testing.T) {
	sda := Device{Name: "sda", Children: []Device{{}}}

	tests := map[string]struct {
		devicePaths      []string
		mockedStdout     string
		mockedDevices    []Device
		mockedExitStatus int
		wantErr          bool
	}{
		"Basic": {
			devicePaths:   []string{"/dev/sda"},
			mockedDevices: []Device{sda},
		},
		"NotABlockDevice": {
			devicePaths:      []string{"/dev/sdzz"},
			mockedStdout:     "lsblk: sdzz: not a block device",
			mockedExitStatus: 32,
		},
		"InvalidJson": {
			mockedStdout:     "{",
			mockedExitStatus: 0,
			wantErr:          true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			mockedStdout := tt.mockedStdout
			if mockedStdout == "" {
				out, err := json.Marshal(deviceInfo{BlockDevices: tt.mockedDevices})
				assert.Nil(err, "could not setup test")
				mockedStdout = string(out)
			}

			defer gostub.Stub(&execCommand, makeFakeExecCommand(tt.mockedExitStatus, mockedStdout)).Reset()
			deviceInfo, err := lsblk(tt.devicePaths)

			if tt.mockedExitStatus != 0 || tt.wantErr {
				assert.Nil(deviceInfo)
				assert.NotNil(err)
			} else {
				assert.NotNil(deviceInfo)
				assert.Equal(tt.mockedDevices, deviceInfo.BlockDevices)
				assert.Nil(err)
			}
		})
	}
}

func TestConnectorPersistance(t *testing.T) {
	assert := assert.New(t)

	secret := Secrets{
		SecretsType: "fake secret type",
		UserName:    "fake username",
		Password:    "fake password",
		UserNameIn:  "fake username in",
		PasswordIn:  "fake password in",
	}
	childDevice := Device{
		Name:      "child name",
		Hctl:      "child hctl",
		Type:      "child type",
		Transport: "child transport",
	}
	device := Device{
		Name:      "device name",
		Hctl:      "device hctl",
		Children:  []Device{childDevice},
		Type:      "device type",
		Transport: "device transport",
	}
	c := Connector{
		VolumeName:        "fake volume name",
		Targets:           []TargetInfo{},
		Lun:               42,
		AuthType:          "fake auth type",
		DiscoverySecrets:  secret,
		SessionSecrets:    secret,
		Interface:         "fake interface",
		MountTargetDevice: &device,
		Devices:           []Device{childDevice},
		RetryCount:        24,
		CheckInterval:     13,
		DoDiscovery:       true,
		DoCHAPDiscovery:   true,
	}

	defer gostub.Stub(&execCommand, func(cmd string, args ...string) *exec.Cmd {
		mockedDevice := device
		if args[3] == "/dev/child name" {
			mockedDevice = childDevice
		}

		mockedOutput, err := json.Marshal(deviceInfo{BlockDevices: []Device{mockedDevice}})
		assert.Nil(err, "could not setup test")

		return makeFakeExecCommand(0, string(mockedOutput))(cmd, args...)
	}).Reset()

	c.Persist("/tmp/connector.json")
	c2, err := GetConnectorFromFile("/tmp/connector.json")
	assert.Nil(err)
	assert.Equal(c, *c2)

	err = c.Persist("/tmp")
	assert.NotNil(err)

	os.Remove("/tmp/shouldNotExists.json")
	_, err = GetConnectorFromFile("/tmp/shouldNotExists.json")
	assert.NotNil(err)
	assert.IsType(&os.PathError{}, err)

	ioutil.WriteFile("/tmp/connector.json", []byte("not a connector"), 0600)
	_, err = GetConnectorFromFile("/tmp/connector.json")
	assert.NotNil(err)
	assert.IsType(&json.SyntaxError{}, err)
}

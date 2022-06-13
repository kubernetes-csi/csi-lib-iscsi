package iscsi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k8s.io/klog/v2"
)

const defaultPort = "3260"

var (
	execCommand        = exec.Command
	execCommandContext = exec.CommandContext
	execWithTimeout    = ExecWithTimeout
	osStat             = os.Stat
	filepathGlob       = filepath.Glob
	osOpenFile         = os.OpenFile
	sleep              = time.Sleep
)

// iscsiSession contains information avout an iSCSI session
type iscsiSession struct {
	Protocol string
	ID       int32
	Portal   string
	IQN      string
	Name     string
}

type deviceInfo []Device

// Device contains information about a device
type Device struct {
	Name      string   `json:"name"`
	Hctl      string   `json:"hctl"`
	Children  []Device `json:"children"`
	Type      string   `json:"type"`
	Transport string   `json:"tran"`
	Size      string   `json:"size,omitempty"`
}

type HCTL struct {
	HBA     int
	Channel int
	Target  int
	LUN     int
}

// Connector provides a struct to hold all of the needed parameters to make our iSCSI connection
type Connector struct {
	VolumeName       string   `json:"volume_name"`
	TargetIqn        string   `json:"target_iqn"`
	TargetPortals    []string `json:"target_portal"`
	Lun              int32    `json:"lun"`
	AuthType         string   `json:"auth_type"`
	DiscoverySecrets Secrets  `json:"discovery_secrets"`
	SessionSecrets   Secrets  `json:"session_secrets"`
	Interface        string   `json:"interface"`

	MountTargetDevice *Device  `json:"mount_target_device"`
	Devices           []Device `json:"devices"`

	RetryCount      uint `json:"retry_count"`
	CheckInterval   uint `json:"check_interval"`
	DoDiscovery     bool `json:"do_discovery"`
	DoCHAPDiscovery bool `json:"do_chap_discovery"`
}

var version string = "1.0.0"

// parseSession takes the raw stdout from the iscsiadm -m session command and encodes it into an iSCSI session type
func parseSessions(lines string) []iscsiSession {
	entries := strings.Split(strings.TrimSpace(lines), "\n")
	r := strings.NewReplacer("[", "",
		"]", "")

	var sessions []iscsiSession
	for _, entry := range entries {
		e := strings.Fields(entry)
		if len(e) < 4 {
			continue
		}
		protocol := strings.Split(e[0], ":")[0]
		id := r.Replace(e[1])
		id64, _ := strconv.ParseInt(id, 10, 32)
		portal := strings.Split(e[2], ",")[0]

		s := iscsiSession{
			Protocol: protocol,
			ID:       int32(id64),
			Portal:   portal,
			IQN:      e[3],
			Name:     strings.Split(e[3], ":")[1],
		}
		sessions = append(sessions, s)
	}
	return sessions
}

// sessionExists checks if an iSCSI session exists
func sessionExists(ctx context.Context, tgtPortal, tgtIQN string) (bool, error) {
	sessions, err := getCurrentSessions(ctx)
	if err != nil {
		return false, err
	}
	for _, s := range sessions {
		if tgtIQN == s.IQN && tgtPortal == s.Portal {
			return true, nil
		}
	}
	return false, nil
}

// extractTransportName returns a transport_name from getCurrentSessions output
func extractTransportName(output string) string {
	res := regexp.MustCompile(`iface.transport_name = (.*)\n`).FindStringSubmatch(output)
	if res == nil {
		return ""
	}
	if res[1] == "" {
		return "tcp"
	}
	return res[1]
}

// getCurrentSessions list current iSCSI sessions
func getCurrentSessions(ctx context.Context) ([]iscsiSession, error) {
	out, err := GetSessions(ctx)
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ProcessState.Sys().(syscall.WaitStatus).ExitStatus() == 21 {
			return []iscsiSession{}, nil
		}
		return nil, err
	}
	sessions := parseSessions(out)
	return sessions, err
}

// waitForPathToExist wait for a file at a path to exists on disk
func waitForPathToExist(ctx context.Context, devicePath *string, maxRetries, intervalSeconds uint, deviceTransport string) error {
	logger := klog.FromContext(ctx)
	if devicePath == nil || *devicePath == "" {
		return fmt.Errorf("unable to check unspecified devicePath")
	}

	for i := uint(0); i <= maxRetries; i++ {
		if i != 0 {
			logger.V(1).Info("Device path doesn't exists yet, retrying", "device", *devicePath, "seconds", intervalSeconds, "retries", 1, "max", maxRetries)
			sleep(time.Second * time.Duration(intervalSeconds))
		}

		if err := pathExists(ctx, devicePath, deviceTransport); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	return os.ErrNotExist
}

// pathExists checks if a file at a path exists on disk
func pathExists(ctx context.Context, devicePath *string, deviceTransport string) error {
	logger := klog.FromContext(ctx)
	if deviceTransport == "tcp" {
		_, err := osStat(*devicePath)
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Error(err, "Error attempting to stat device")
				return err
			}
			logger.V(1).Info("Device not found", "device", *devicePath)
			return err
		}
	} else {
		fpath, err := filepathGlob(*devicePath)

		if err != nil {
			return err
		}
		if fpath == nil {
			return os.ErrNotExist
		}
		// There might be a case that fpath contains multiple device paths if
		// multiple PCI devices connect to same iscsi target. We handle this
		// case at subsequent logic. Pick up only first path here.
		*devicePath = fpath[0]
	}

	return nil
}

// getMultipathDevice returns a multipath device for the configured targets if it exists
func getMultipathDevice(ctx context.Context, devices []Device) (*Device, error) {
	logger := klog.FromContext(ctx)
	var multipathDevice *Device

	// This routine relies on output from lsblk, and older versions did not produce the desired outcome
	// of a child row, followed by a parent row. This routine now just takes the first parent found.
	for _, device := range devices {
		logger.V(1).Info("find multipath device", "device", device)
		if len(device.Children) != 1 {
			logger.V(1).Info("WARNING: children != 1", "name", device.Name)
		}
		if len(device.Children) == 1 {
			multipathDevice = &device.Children[0]
			logger.V(1).Info("SET: multipath device", "name", multipathDevice.Name)
			break
		}
	}

	if multipathDevice == nil {
		return nil, fmt.Errorf("multipath device not found")
	}

	if multipathDevice.Type != "mpath" {
		return nil, fmt.Errorf("device is not of mpath type: %v", multipathDevice)
	}

	return multipathDevice, nil
}

// Connect is for backward-compatibility with c.Connect()
func Connect(ctx context.Context, c Connector) (string, error) {
	return c.Connect(ctx)
}

// Connect attempts to connect a volume to this node using the provided Connector info
func (c *Connector) Connect(ctx context.Context) (string, error) {

	logger := klog.FromContext(ctx)
	logger.Info("[] csi-lib-iscsi connect", "version", version)

	if c.RetryCount == 0 {
		c.RetryCount = 10
	}
	if c.CheckInterval == 0 {
		c.CheckInterval = 1
	}

	iFace := "default"
	if c.Interface != "" {
		iFace = c.Interface
	}

	// make sure our iface exists and extract the transport type
	out, err := ShowInterface(ctx, iFace)
	if err != nil {
		return "", err
	}
	iscsiTransport := extractTransportName(out)

	var lastErr error
	var devicePaths []string
	for _, target := range c.TargetPortals {
		devicePath, err := c.connectTarget(ctx, c.TargetIqn, target, iFace, iscsiTransport)
		if err != nil {
			lastErr = err
		} else {
			logger.V(1).Info("Appending device path", "device", devicePath)
			devicePaths = append(devicePaths, devicePath)
		}
	}

	// GetISCSIDevices returns all devices if no paths are given
	if len(devicePaths) < 1 {
		c.Devices = []Device{}
	} else if c.Devices, err = GetISCSIDevices(ctx, devicePaths, true); err != nil {
		return "", err
	}

	if len(c.Devices) < 1 {
		logger.Error(lastErr, "failed to find device path", "length", len(c.Devices))
		iscsiCmd(ctx, []string{"-m", "iface", "-I", iFace, "-o", "delete"}...)
		return "", fmt.Errorf("failed to find device path: %s, last error seen: %v", devicePaths, lastErr)
	}

	mountTargetDevice, err := c.getMountTargetDevice(ctx)
	c.MountTargetDevice = mountTargetDevice
	if err != nil {
		logger.Error(err, "Connect failed")
		err := RemoveSCSIDevices(ctx, c.Devices...)
		if err != nil {
			return "", err
		}
		c.MountTargetDevice = nil
		c.Devices = []Device{}
		return "", err
	}

	if c.IsMultipathEnabled() {
		if err := c.IsMultipathConsistent(ctx); err != nil {
			return "", fmt.Errorf("multipath is inconsistent: %v", err)
		}
	}

	return c.MountTargetDevice.GetPath(), nil
}

func (c *Connector) connectTarget(ctx context.Context, targetIqn string, target string, iFace string, iscsiTransport string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Connect target", "iqn", targetIqn, "portal", target)
	targetParts := strings.Split(target, ":")
	targetPortal := targetParts[0]
	targetPort := defaultPort
	if len(targetParts) > 1 {
		targetPort = targetParts[1]
	}
	baseArgs := []string{"-m", "node", "-T", targetIqn, "-p", targetPortal}
	// Rescan sessions to discover newly mapped LUNs. Do not specify the interface when rescanning
	// to avoid establishing additional sessions to the same target.
	if _, err := iscsiCmd(ctx, append(baseArgs, []string{"-R"}...)...); err != nil {
		logger.Error(err, "Failed to rescan session")
		if os.IsTimeout(err) {
			logger.V(1).Info("iscsiadm timed out, logging out")
			cmd := execCommand("iscsiadm", append(baseArgs, []string{"-u"}...)...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("could not logout from target: %s", out)
			}
		}
	}

	// create our devicePath that we'll be looking for based on the transport being used
	// portal with port
	portal := strings.Join([]string{targetPortal, targetPort}, ":")
	devicePath := strings.Join([]string{"/dev/disk/by-path/ip", portal, "iscsi", targetIqn, "lun", fmt.Sprint(c.Lun)}, "-")
	if iscsiTransport != "tcp" {
		devicePath = strings.Join([]string{"/dev/disk/by-path/pci", "*", "ip", portal, "iscsi", targetIqn, "lun", fmt.Sprint(c.Lun)}, "-")
	}

	exists, _ := sessionExists(ctx, portal, targetIqn)
	if exists {
		logger.V(1).Info("Session already exists, checking if device path exists", "device", devicePath)
		if err := waitForPathToExist(ctx, &devicePath, c.RetryCount, c.CheckInterval, iscsiTransport); err != nil {
			return "", err
		}
		return devicePath, nil
	}

	if err := c.discoverTarget(ctx, targetIqn, iFace, portal); err != nil {
		return "", err
	}

	// perform the login
	err := Login(ctx, targetIqn, portal)
	if err != nil {
		logger.Error(err, "Failed to login")
		return "", err
	}

	logger.V(1).Info("Waiting for device path to exist", "device", devicePath)
	if err := waitForPathToExist(ctx, &devicePath, c.RetryCount, c.CheckInterval, iscsiTransport); err != nil {
		return "", err
	}

	return devicePath, nil
}

func (c *Connector) discoverTarget(ctx context.Context, targetIqn string, iFace string, portal string) error {
	logger := klog.FromContext(ctx)
	if c.DoDiscovery {
		// build discoverydb and discover iscsi target
		if err := Discoverydb(ctx, portal, iFace, c.DiscoverySecrets, c.DoCHAPDiscovery); err != nil {
			logger.Error(err, "Error in discovery of the target")
			return err
		}
	}

	if c.DoCHAPDiscovery {
		// Make sure we don't log the secrets
		err := CreateDBEntry(ctx, targetIqn, portal, iFace, c.DiscoverySecrets, c.SessionSecrets)
		if err != nil {
			logger.Error(err, "Error creating db entry")
			return err
		}
	}

	return nil
}

// Disconnect is for backward-compatibility with c.Disconnect()
func Disconnect(ctx context.Context, targetIqn string, targets []string) {
	for _, target := range targets {
		targetPortal := strings.Split(target, ":")[0]
		err := Logout(ctx, targetIqn, targetPortal)
		if err != nil {
			return
		}
	}

	deleted := map[string]bool{}
	if _, ok := deleted[targetIqn]; ok {
		return
	}
	deleted[targetIqn] = true
	err := DeleteDBEntry(ctx, targetIqn)
	if err != nil {
		return
	}
}

// Disconnect performs a disconnect operation from an appliance.
// Be sure to disconnect all devices properly before doing this as it can result in data loss.
func (c *Connector) Disconnect(ctx context.Context) {
	Disconnect(ctx, c.TargetIqn, c.TargetPortals)
}

// DisconnectVolume removes a volume from a Linux host.
func (c *Connector) DisconnectVolume(ctx context.Context) error {
	// Steps to safely remove an iSCSI storage volume from a Linux host are as following:
	// 1. Unmount the disk from a filesystem on the system.
	// 2. Flush the multipath map for the disk we’re removing (if multipath is enabled).
	// 3. Remove the physical disk entities that Linux maintains.
	// 4. Take the storage volume (disk) offline on the storage subsystem.
	// 5. Rescan the iSCSI sessions (after unmapping only).
	//
	// DisconnectVolume focuses on step 2 and 3.
	// Note: make sure the volume is already unmounted before calling this method.

	logger := klog.FromContext(ctx)

	if c.IsMultipathEnabled() {
		if err := c.IsMultipathConsistent(ctx); err != nil {
			return fmt.Errorf("multipath is inconsistent: %v", err)
		}

		logger.V(1).Info("Removing multipath device in path", "device", c.MountTargetDevice.GetPath())
		err := FlushMultipathDevice(ctx, c.MountTargetDevice)
		if err != nil {
			return err
		}
		if err := RemoveSCSIDevices(ctx, c.Devices...); err != nil {
			return err
		}
	} else {
		devicePath := c.MountTargetDevice.GetPath()
		logger.V(1).Info("Removing normal device in path", "device", devicePath)
		if err := RemoveSCSIDevices(ctx, *c.MountTargetDevice); err != nil {
			return err
		}
	}

	logger.V(1).Info("Finished disconnecting volume.")
	return nil
}

// getMountTargetDevice returns the device to be mounted among the configured devices
func (c *Connector) getMountTargetDevice(ctx context.Context) (*Device, error) {
	logger := klog.FromContext(ctx)
	if len(c.Devices) > 1 {
		multipathDevice, err := getMultipathDevice(ctx, c.Devices)
		if err != nil {
			logger.Error(err, "Mount target is not a multipath device")
			return nil, err
		}
		logger.V(1).Info("Mount target is a multipath device")
		return multipathDevice, nil
	}

	if len(c.Devices) == 0 {
		return nil, fmt.Errorf("could not find mount target device: connector does not contain any device")
	}

	return &c.Devices[0], nil
}

// IsMultipathEnabled check if multipath is enabled on devices handled by this connector
func (c *Connector) IsMultipathEnabled() bool {
	return c.MountTargetDevice.Type == "mpath"
}

// GetSCSIDevices get SCSI devices from device paths
// It will returns all SCSI devices if no paths are given
func GetSCSIDevices(ctx context.Context, devicePaths []string, strict bool) ([]Device, error) {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Getting info about SCSI devices", "devices", devicePaths)

	deviceInfo, err := lsblk(ctx, devicePaths, strict)
	if err != nil {
		logger.Error(err, "An error occurred while looking info about SCSI devices")
		return nil, err
	}

	return deviceInfo, nil
}

// GetISCSIDevices get iSCSI devices from device paths
// It will returns all iSCSI devices if no paths are given
func GetISCSIDevices(ctx context.Context, devicePaths []string, strict bool) (devices []Device, err error) {
	logger := klog.FromContext(ctx)
	scsiDevices, err := GetSCSIDevices(ctx, devicePaths, strict)
	if err != nil {
		return
	}

	for i := range scsiDevices {
		device := &scsiDevices[i]
		if device.Transport == "iscsi" {
			logger.V(1).Info("append iscsi device", "device", *device)
			devices = append(devices, *device)
		}
	}

	return
}

// lsblk execute the lsblk commands
func lsblk(ctx context.Context, devicePaths []string, strict bool) (deviceInfo, error) {
	logger := klog.FromContext(ctx)
	flags := []string{"-rn", "-o", "NAME,KNAME,PKNAME,HCTL,TYPE,TRAN,SIZE"}
	command := execCommand("lsblk", append(flags, devicePaths...)...)
	logger.V(1).Info("lsblk", "command", command.String())
	out, err := command.Output()
	logger.V(1).Info("lsblk", "output", out, "error", "err")
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%s, (%w)", strings.Trim(string(ee.Stderr), "\n"), ee)
			if strict || ee.ExitCode() != 64 { // ignore the error if some devices have been found when not strict
				return nil, err
			}
			logger.Error(err, "Could find only some devices")
		} else {
			return nil, err
		}
	}

	var devices []*Device
	devicesMap := make(map[string]*Device)
	pkNames := []string{}

	// Parse devices
	lines := strings.Split(strings.Trim(string(out), "\n"), "\n")
	for _, line := range lines {
		columns := strings.Split(line, " ")
		logger.V(1).Info("parse devices", "columns", columns)
		if len(columns) < 5 {
			logger.V(1).Info("invalid output from lsblk", "line", line)
			return nil, fmt.Errorf("invalid output from lsblk: %s", line)
		}
		device := &Device{
			Name:      columns[0],
			Hctl:      columns[3],
			Type:      columns[4],
			Transport: columns[5],
			Size:      columns[6],
		}
		logger.V(1).Info("append device", "column1", columns[1], "column2", columns[2], "device", device)
		devices = append(devices, device)
		pkNames = append(pkNames, columns[2])
		devicesMap[columns[1]] = device
	}

	// Reconstruct devices tree
	for i, pkName := range pkNames {
		if pkName == "" {
			continue
		}
		device := devices[i]
		parent, ok := devicesMap[pkName]
		if !ok {
			return nil, fmt.Errorf("invalid output from lsblk: parent device %q not found", pkName)
		}
		if parent.Children == nil {
			parent.Children = []Device{}
		}
		logger.V(1).Info("append child", "pkName", pkName, "device", *device)
		parent.Children = append(devicesMap[pkName].Children, *device)
	}

	// Filter devices to keep only the roots of the tree
	var deviceInfo deviceInfo
	for i, device := range devices {
		if pkNames[i] == "" {
			logger.V(1).Info("append device info", "pkName", pkNames[i], "device", *device)
			deviceInfo = append(deviceInfo, *device)
		}
	}

	return deviceInfo, nil
}

// writeInSCSIDeviceFile write into special devices files to change devices state
func writeInSCSIDeviceFile(ctx context.Context, hctl string, file string, content string) error {
	logger := klog.FromContext(ctx)
	filename := filepath.Join("/sys/class/scsi_device", hctl, "device", file)
	logger.V(1).Info("Write to SCSI device", "content", content, "filename", filename)

	f, err := osOpenFile(filename, os.O_TRUNC|os.O_WRONLY, 0200)
	if err != nil {
		logger.Error(err, "Error attempting to open file", "filename", filename)
		return err
	}

	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		logger.Error(err, "Error attempting to write to file", "filename", filename)
		return err
	}

	return nil
}

// RemoveSCSIDevices removes SCSI device(s) from a Linux host.
func RemoveSCSIDevices(ctx context.Context, devices ...Device) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Removing SCSI devices", "devices", devices)

	var errs []error
	for _, device := range devices {
		logger.V(1).Info("Flush SCSI device", "device", device.Name)
		if err := device.Exists(); err == nil {
			out, err := execCommand("blockdev", "--flushbufs", device.GetPath()).CombinedOutput()
			if err != nil {
				logger.Error(err, "Command 'blockdev --flushbufs <device>' did not succeed to flush the device", "device", device.GetPath())
				return errors.New(string(out))
			}
		} else if !os.IsNotExist(err) {
			return err
		}

		logger.V(1).Info("Put SCSI device offline", "device", device.Name)
		err := device.Shutdown(ctx)
		if err != nil {
			if !os.IsNotExist(err) { // Ignore device already removed
				errs = append(errs, err)
			}
			continue
		}

		logger.V(1).Info("Delete SCSI device", "device", device.Name)
		err = device.Delete(ctx)
		if err != nil {
			if !os.IsNotExist(err) { // Ignore device already removed
				errs = append(errs, err)
			}
			continue
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	logger.V(1).Info("Finished removing SCSI devices.")
	return nil
}

// PersistConnector is for backward-compatibility with c.Persist()
func PersistConnector(c *Connector, filePath string) error {
	return c.Persist(filePath)
}

// Persist persists the Connector to the specified file (ie /var/lib/pfile/myConnector.json)
func (c *Connector) Persist(filePath string) error {
	//file := path.Join("mnt", c.VolumeName+".json")
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating iSCSI persistence file %s: %s", filePath, err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	if err = encoder.Encode(c); err != nil {
		return fmt.Errorf("error encoding connector: %v", err)
	}
	return nil
}

// GetConnectorFromFile attempts to create a Connector using the specified json file (ie /var/lib/pfile/myConnector.json)
func GetConnectorFromFile(ctx context.Context, filePath string) (*Connector, error) {
	f, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	c := Connector{}
	err = json.Unmarshal([]byte(f), &c)
	if err != nil {
		return nil, err
	}

	devicePaths := []string{}
	for _, device := range c.Devices {
		devicePaths = append(devicePaths, device.GetPath())
	}
	if c.MountTargetDevice == nil {
		return nil, fmt.Errorf("mountTargetDevice in the connector is nil")
	}
	if devices, err := GetSCSIDevices(ctx, []string{c.MountTargetDevice.GetPath()}, false); err != nil {
		return nil, err
	} else {
		c.MountTargetDevice = &devices[0]
	}

	if c.Devices, err = GetSCSIDevices(ctx, devicePaths, false); err != nil {
		return nil, err
	}

	return &c, nil
}

// IsMultipathConsistent check if the currently used device is using a consistent multipath mapping
func (c *Connector) IsMultipathConsistent(ctx context.Context) error {
	devices := append([]Device{*c.MountTargetDevice}, c.Devices...)

	referenceLUN := struct {
		LUN  int
		Name string
	}{LUN: -1, Name: ""}
	HBA := map[int]string{}
	referenceDevice := devices[0]
	for _, device := range devices {
		if device.Size != referenceDevice.Size {
			return fmt.Errorf("devices size differ: %s (%s) != %s (%s)", device.Name, device.Size, referenceDevice.Name, referenceDevice.Size)
		}

		if device.Type != "mpath" {
			hctl, err := device.HCTL()
			if err != nil {
				return err
			}
			if referenceLUN.LUN == -1 {
				referenceLUN.LUN = hctl.LUN
				referenceLUN.Name = device.Name
			} else if hctl.LUN != referenceLUN.LUN {
				return fmt.Errorf("devices LUNs differ: %s (%d) != %s (%d)", device.Name, hctl.LUN, referenceLUN.Name, referenceLUN.LUN)
			}

			if name, ok := HBA[hctl.HBA]; !ok {
				HBA[hctl.HBA] = device.Name
			} else {
				return fmt.Errorf("two devices are using the same controller (%d): %s and %s", hctl.HBA, device.Name, name)
			}
		}

		wwid, err := device.WWID(ctx)
		if err != nil {
			return fmt.Errorf("could not find WWID for device %s: %v", device.Name, err)
		}
		if wwid != referenceDevice.Name {
			return fmt.Errorf("devices WWIDs differ: %s (wwid:%s) != %s (wwid:%s)", device.Name, wwid, referenceDevice.Name, referenceDevice.Name)
		}
	}

	return nil
}

// Exists check if the device exists at its path and returns an error otherwise
func (d *Device) Exists() error {
	_, err := osStat(d.GetPath())
	return err
}

// GetPath returns the path of a device
func (d *Device) GetPath() string {
	if d.Type == "mpath" {
		return filepath.Join("/dev/mapper", d.Name)
	}

	return filepath.Join("/dev", d.Name)
}

// WWID returns the WWID of a device
func (d *Device) WWID(ctx context.Context) (string, error) {
	timeout := 1 * time.Second
	out, err := execWithTimeout(ctx, "scsi_id", []string{"-g", "-u", d.GetPath()}, timeout)
	if err != nil {
		return "", err
	}

	return string(out[:len(out)-1]), nil
}

// HCTL returns the HCTL of a device
func (d *Device) HCTL() (*HCTL, error) {
	var hctl []int

	for _, idstr := range strings.Split(d.Hctl, ":") {
		id, err := strconv.Atoi(idstr)
		if err != nil {
			hctl = []int{}
			break
		}
		hctl = append(hctl, id)
	}

	if len(hctl) != 4 {
		return nil, fmt.Errorf("invalid HCTL (%s) for device %q", d.Hctl, d.Name)
	}

	return &HCTL{
		HBA:     hctl[0],
		Channel: hctl[1],
		Target:  hctl[2],
		LUN:     hctl[3],
	}, nil
}

// WriteDeviceFile write in a device file
func (d *Device) WriteDeviceFile(ctx context.Context, name string, content string) error {
	return writeInSCSIDeviceFile(ctx, d.Hctl, name, content)
}

// Shutdown turn off an SCSI device by writing offline\n in /sys/class/scsi_device/h:c:t:l/device/state
func (d *Device) Shutdown(ctx context.Context) error {
	return d.WriteDeviceFile(ctx, "state", "offline\n")
}

// Delete detach an SCSI device by writing 1 in /sys/class/scsi_device/h:c:t:l/device/delete
func (d *Device) Delete(ctx context.Context) error {
	return d.WriteDeviceFile(ctx, "delete", "1")
}

// Rescan rescan an SCSI device by writing 1 in /sys/class/scsi_device/h:c:t:l/device/rescan
func (d *Device) Rescan(ctx context.Context) error {
	return d.WriteDeviceFile(ctx, "rescan", "1")
}

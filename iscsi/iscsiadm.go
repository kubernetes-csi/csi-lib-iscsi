package iscsi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// Secrets provides optional iscsi security credentials (CHAP settings)
type Secrets struct {
	// SecretsType is the type of Secrets being utilized (currently we only impleemnent "chap"
	SecretsType string `json:"secretsType,omitempty"`
	// UserName is the configured iscsi user login
	UserName string `json:"userName"`
	// Password is the configured iscsi password
	Password string `json:"password"`
	// UserNameIn provides a specific input login for directional CHAP configurations
	UserNameIn string `json:"userNameIn,omitempty"`
	// PasswordIn provides a specific input password for directional CHAP configurations
	PasswordIn string `json:"passwordIn,omitempty"`
}

func iscsiCmd(ctx context.Context, args ...string) (string, error) {
	logger := klog.FromContext(ctx)
	stdout, err := execWithTimeout(ctx, "iscsiadm", args, time.Second*3)

	logger.V(1).Info("Run iscsiadm", "command", strings.Join(append([]string{"iscsiadm"}, args...), " "))
	iscsiadmDebug(ctx, string(stdout), err)

	return string(stdout), err
}

func iscsiadmDebug(ctx context.Context, output string, cmdError error) {
	logger := klog.FromContext(ctx)
	debugOutput := strings.Replace(output, "\n", "\\n", -1)
	logger.V(1).Info("Output of iscsiadm command", "output", debugOutput)
	if cmdError != nil {
		klog.ErrorS(cmdError, "Error message returned from iscsiadm command")
	}
}

// ListInterfaces returns a list of all iscsi interfaces configured on the node
/// along with the raw output in Response.StdOut we add the convenience of
// returning a list of entries found
func ListInterfaces(ctx context.Context) ([]string, error) {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin ListInterface...")
	out, err := iscsiCmd(ctx, "-m", "iface", "-o", "show")
	return strings.Split(out, "\n"), err
}

// ShowInterface retrieves the details for the specified iscsi interface
// caller should inspect r.Err and use r.StdOut for interface details
func ShowInterface(ctx context.Context, iface string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin ShowInterface...")
	out, err := iscsiCmd(ctx, "-m", "iface", "-o", "show", "-I", iface)
	return out, err
}

// CreateDBEntry sets up a node entry for the specified tgt in the nodes iscsi nodes db
func CreateDBEntry(ctx context.Context, tgtIQN, portal, iFace string, discoverySecrets, sessionSecrets Secrets) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin CreateDBEntry...")
	baseArgs := []string{"-m", "node", "-T", tgtIQN, "-p", portal}
	_, err := iscsiCmd(ctx, append(baseArgs, "-I", iFace, "-o", "new")...)
	if err != nil {
		return err
	}

	if discoverySecrets.SecretsType == "chap" {
		logger.V(1).Info("Setting CHAP Discovery...")
		err := createCHAPEntries(ctx, baseArgs, discoverySecrets, true)
		if err != nil {
			return err
		}
	}

	if sessionSecrets.SecretsType == "chap" {
		logger.V(1).Info("Setting CHAP Session...")
		err := createCHAPEntries(ctx, baseArgs, sessionSecrets, false)
		if err != nil {
			return err
		}
	}

	return err

}

// Discoverydb discovers the iscsi target
func Discoverydb(ctx context.Context, tp, iface string, discoverySecrets Secrets, chapDiscovery bool) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin Discoverydb...")
	baseArgs := []string{"-m", "discoverydb", "-t", "sendtargets", "-p", tp, "-I", iface}
	out, err := iscsiCmd(ctx, append(baseArgs, []string{"-o", "new"}...)...)
	if err != nil {
		return fmt.Errorf("failed to create new entry of target in discoverydb, output: %v, err: %v", out, err)
	}

	if chapDiscovery {
		if err := createCHAPEntries(ctx, baseArgs, discoverySecrets, true); err != nil {
			return err
		}
	}

	_, err = iscsiCmd(ctx, append(baseArgs, []string{"--discover"}...)...)
	if err != nil {
		//delete the discoverydb record
		iscsiCmd(ctx, append(baseArgs, []string{"-o", "delete"}...)...)
		return fmt.Errorf("failed to sendtargets to portal %s, err: %v", tp, err)
	}
	return nil
}

func createCHAPEntries(ctx context.Context, baseArgs []string, secrets Secrets, discovery bool) error {
	logger := klog.FromContext(ctx)
	args := []string{}
	logger.V(1).Info("Begin createCHAPEntries...", "discovery", discovery)
	if discovery {
		args = append(baseArgs, []string{"-o", "update",
			"-n", "discovery.sendtargets.auth.authmethod", "-v", "CHAP",
			"-n", "discovery.sendtargets.auth.username", "-v", secrets.UserName,
			"-n", "discovery.sendtargets.auth.password", "-v", secrets.Password}...)
		if secrets.UserNameIn != "" {
			args = append(args, []string{"-n", "discovery.sendtargets.auth.username_in", "-v", secrets.UserNameIn}...)
		}
		if secrets.PasswordIn != "" {
			args = append(args, []string{"-n", "discovery.sendtargets.auth.password_in", "-v", secrets.PasswordIn}...)
		}

	} else {

		args = append(baseArgs, []string{"-o", "update",
			"-n", "node.session.auth.authmethod", "-v", "CHAP",
			"-n", "node.session.auth.username", "-v", secrets.UserName,
			"-n", "node.session.auth.password", "-v", secrets.Password}...)
		if secrets.UserNameIn != "" {
			args = append(args, []string{"-n", "node.session.auth.username_in", "-v", secrets.UserNameIn}...)
		}
		if secrets.PasswordIn != "" {
			args = append(args, []string{"-n", "node.session.auth.password_in", "-v", secrets.PasswordIn}...)
		}
	}

	_, err := iscsiCmd(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to update discoverydb with CHAP, err: %v", err)
	}

	return nil
}

// GetSessions retrieves a list of current iscsi sessions on the node
func GetSessions(ctx context.Context) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin GetSessions...")
	out, err := iscsiCmd(ctx, "-m", "session")
	return out, err
}

// Login performs an iscsi login for the specified target
func Login(ctx context.Context, tgtIQN, portal string) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin Login...")
	baseArgs := []string{"-m", "node", "-T", tgtIQN, "-p", portal}
	if _, err := iscsiCmd(ctx, append(baseArgs, []string{"-l"}...)...); err != nil {
		//delete the node record from database
		iscsiCmd(ctx, append(baseArgs, []string{"-o", "delete"}...)...)
		return fmt.Errorf("failed to sendtargets to portal %s, err: %v", portal, err)
	}
	return nil
}

// Logout logs out the specified target
func Logout(ctx context.Context, tgtIQN, portal string) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin Logout...")
	args := []string{"-m", "node", "-T", tgtIQN, "-p", portal, "-u"}
	iscsiCmd(ctx, args...)
	return nil
}

// DeleteDBEntry deletes the iscsi db entry for the specified target
func DeleteDBEntry(ctx context.Context, tgtIQN string) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin DeleteDBEntry...")
	args := []string{"-m", "node", "-T", tgtIQN, "-o", "delete"}
	iscsiCmd(ctx, args...)
	return nil
}

// DeleteIFace delete the iface
func DeleteIFace(ctx context.Context, iface string) error {
	logger := klog.FromContext(ctx)
	logger.V(1).Info("Begin DeleteIFace...")
	iscsiCmd(ctx, []string{"-m", "iface", "-I", iface, "-o", "delete"}...)
	return nil
}

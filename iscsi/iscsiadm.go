package iscsi

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
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

// CmdError is a custom error to provide details including the command, stderr output and exit code.
// iscsiadm in some cases requires all of this info to determine success or failure
type CmdError struct {
	CMD      string
	StdErr   string
	ExitCode int
}

func (e *CmdError) Error() string {
	// we don't output the command in the error string to avoid leaking any security info
	// the command is still available in the error structure if the caller wants it though
	return fmt.Sprintf("iscsiadm returned an error: %s, exit-code: %d", e.StdErr, e.ExitCode)
}

func iscsiCmd(args ...string) (string, error) {
	cmd := execCommand("iscsiadm", args...)
	var stdout bytes.Buffer
	var iscsiadmError error
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	defer stdout.Reset()

	// we're using Start and Wait because we want to grab exit codes
	err := cmd.Start()
	if err != nil {
		// This is usually a cmd not found so we'll set our own error here
		formattedOutput := strings.Replace(string(stdout.Bytes()), "\n", "", -1)
		iscsiadmError = fmt.Errorf("iscsiadm error: %s (%s)", formattedOutput, err.Error())

	} else {
		err = cmd.Wait()
		if err != nil {
			formattedOutput := strings.Replace(string(stdout.Bytes()), "\n", "", -1)
			iscsiadmError = fmt.Errorf("iscsiadm error: %s (%s)", formattedOutput, err.Error())

		}
	}

	iscsiadmDebug(args, string(stdout.Bytes()), iscsiadmError)
	return string(stdout.Bytes()), iscsiadmError
}

func iscsiadmDebug(args []string, output string, cmdError error) {
	debugOutput := strings.Replace(output, "\n", "\\n", -1)
	debug.Printf("Output of iscsiadm command: {{cmd: iscsiadm %s}, {output: %s}", args, debugOutput)
	if cmdError != nil {
		debug.Printf("Error message returned from issiadm command: %s", cmdError.Error())
	}
}

func iscsiCmdHide(args ...string) (string, error) {
	debug.Printf("Execute iscsiadm %s", args)
	var waitStatus syscall.WaitStatus
	var iscsiHelper = "iscsiadm"
	eStat := 0
	out := &bytes.Buffer{}
	cmdErr := &bytes.Buffer{}

	c := execCommand(iscsiHelper, args...)
	c.Stdout = out
	c.Stderr = cmdErr
	iscsiadmErr := CmdError{}

	if err := c.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			eStat = waitStatus.ExitStatus()
		}
	} else {
		waitStatus = c.ProcessState.Sys().(syscall.WaitStatus)
		eStat = waitStatus.ExitStatus()
	}
	if eStat != 0 || string(cmdErr.Bytes()) != "" {
		iscsiadmErr = CmdError{
			StdErr:   string(cmdErr.Bytes()),
			ExitCode: eStat,
			CMD:      iscsiHelper + " " + strings.Join(args, " "),
		}
	}
	if &iscsiadmErr != nil {
		debug.Printf("FUCK: %v\n", &iscsiadmErr)
	}
	debugOutput := strings.Replace(string(out.Bytes()), "\n", "\\n ", -1)
	debugStderr := strings.Replace(string(cmdErr.Bytes()), "\n", "\\n ", -1)

	debug.Printf("Response from iscsiadm, {{output: %s}, {stderr: %s}, {exit-code: %d}}", debugOutput, debugStderr, eStat)
	return string(out.Bytes()), &iscsiadmErr
}

// ListInterfaces returns a list of all iscsi interfaces configured on the node
/// along with the raw output in Response.StdOut we add the convenience of
// returning a list of entries found
func ListInterfaces() ([]string, error) {
	debug.Println("Begin ListInterface...")
	out, err := iscsiCmd("-m", "iface", "-o", "show")
	return strings.Split(out, "\n"), err
}

// ShowInterface retrieves the details for the specified iscsi interface
// caller should inspect r.Err and use r.StdOut for interface details
func ShowInterface(iface string) (string, error) {
	debug.Println("Begin ShowInterface...")
	out, err := iscsiCmd("-m", "iface", "-o", "show", "-I", iface)
	return out, err
}

// CreateDBEntry sets up a node entry for the specified tgt in the nodes iscsi nodes db
func CreateDBEntry(tgtIQN, portal, iFace string, discoverySecrets, sessionSecrets Secrets) error {
	debug.Println("Begin CreateDBEntry...")
	baseArgs := []string{"-m", "node", "-T", tgtIQN, "-p", portal}
	_, err := iscsiCmd(append(baseArgs, []string{"-I", iFace, "-o", "new"}...)...)
	if err != nil {
		return err
	}
	if discoverySecrets.SecretsType == "chap" {
		debug.Printf("Setting CHAP Discovery...")
		createCHAPEntries(baseArgs, discoverySecrets, true)
	}

	if sessionSecrets.SecretsType == "chap" {
		debug.Printf("Setting CHAP Session...")
		createCHAPEntries(baseArgs, sessionSecrets, false)

	}
	return err

}

func createCHAPEntries(baseArgs []string, secrets Secrets, discovery bool) error {
	args := []string{}
	debug.Printf("Begin createCHAPEntries (discovery=%t)...", discovery)
	if discovery {
		args = append(baseArgs, []string{"-o", "update",
			"-n", "node.discovery.auth.authmethod", "-v", "CHAP",
			"-n", "node.discovery.auth.username", "-v", secrets.UserName,
			"-n", "node.discovery.auth.password", "-v", secrets.Password}...)
		if secrets.UserNameIn != "" {
			args = append(args, []string{"-n", "node.discovery.auth.username_in", "-v", secrets.UserNameIn}...)
		}
		if secrets.UserNameIn != "" {
			args = append(args, []string{"-n", "node.discovery.auth.password_in", "-v", secrets.PasswordIn}...)
		}

	} else {

		args = append(baseArgs, []string{"-o", "update",
			"-n", "node.session.auth.authmethod", "-v", "CHAP",
			"-n", "node.session.auth.username", "-v", secrets.UserName,
			"-n", "node.session.auth.password", "-v", secrets.Password}...)
		if secrets.UserNameIn != "" {
			args = append(args, []string{"-n", "node.session.auth.username_in", "-v", secrets.UserNameIn}...)
		}
		if secrets.UserNameIn != "" {
			args = append(args, []string{"-n", "node.session.auth.password_in", "-v", secrets.PasswordIn}...)
		}
	}
	_, err := iscsiCmd(args...)
	return err

}

// GetSessions retrieves a list of current iscsi sessions on the node
func GetSessions() (string, error) {
	debug.Println("Begin GetSessions...")
	out, err := iscsiCmd("-m", "session")
	return out, err
}

// Login performs an iscsi login for the specified target
func Login(tgtIQN, portal string) error {
	_, err := iscsiCmd([]string{"-m", "node", "-T", tgtIQN, "-p", portal, "-l"}...)
	return err
}

// Logout logs out the specified target, if the target is not logged in it's not considered an error
func Logout(tgtIQN string, portals []string) error {
	debug.Println("Begin Logout...")
	baseArgs := []string{"-m", "node", "-T", tgtIQN}
	for _, p := range portals {
		debug.Printf("attempting logout for portal: %s", p)
		args := append(baseArgs, []string{"-p", p, "-u"}...)
		iscsiCmd(args...)
	}
	return nil
}

// DeleteDBEntry deletes the iscsi db entry fo rthe specified target
func DeleteDBEntry(tgtIQN string) error {
	debug.Println("Begin DeleteDBEntry...")
	args := []string{"-m", "node", "-T", tgtIQN, "-o", "delete"}
	iscsiCmd(args...)
	return nil

}

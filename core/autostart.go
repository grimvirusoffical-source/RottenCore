package core

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// AutostartPlan is the launch-at-login file for this OS. The daemon stays in
// the background (Nice / ProcessType) and the supervisor restarts it after a
// self-reset. The file contains the binary path and no secrets.
func AutostartPlan(goos, home, binary string) (path string, data []byte, err error) {
	if binary == "" || home == "" {
		return "", nil, fmt.Errorf("autostart needs a home directory and the rottencore binary")
	}
	switch goos {
	case "darwin":
		path = filepath.Join(home, "Library", "LaunchAgents", "com.redxai.rottencore.daemon.plist")
		data = []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.redxai.rottencore.daemon</string>
<key>ProgramArguments</key><array><string>%s</string><string>daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer>
<key>ProcessType</key><string>Background</string>
<key>EnvironmentVariables</key><dict><key>ROTTENCORE_DAEMON_SUPERVISED</key><string>1</string></dict>
</dict></plist>
`, xmlEscape(binary)))
	case "windows":
		path = filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "RottenCoreDaemon.cmd")
		data = []byte("@echo off\r\nstart \"\" \"" + binary + "\" daemon\r\n")
	default:
		path = filepath.Join(home, ".config", "systemd", "user", "rottencore.service")
		data = []byte(fmt.Sprintf(`[Unit]
Description=RottenCore installer daemon
[Service]
ExecStart=%s daemon
Restart=on-failure
RestartSec=10
Nice=10
MemoryMax=128M
Environment=ROTTENCORE_DAEMON_SUPERVISED=1
[Install]
WantedBy=default.target
`, binary))
	}
	return path, data, nil
}

func xmlEscape(s string) string {
	r := strings.ReplaceAll(s, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	return strings.ReplaceAll(r, ">", "&gt;")
}

// InstallAutostart writes the launch-at-login file for this computer.
func InstallAutostart(home, binary string) (string, error) {
	path, data, err := AutostartPlan(runtime.GOOS, home, binary)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}

// RemoveAutostart deletes the launch-at-login file.
func RemoveAutostart(home string) error {
	path, _, err := AutostartPlan(runtime.GOOS, home, "rottencore")
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errorsIsNotExist(err) {
		return nil
	}
	return err
}

func errorsIsNotExist(err error) bool {
	return os.IsNotExist(err)
}

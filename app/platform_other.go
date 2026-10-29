//go:build !windows

package main

import "os/exec"

// setupConsole 在非 Windows 平台无需处理。
func setupConsole() {}

// prepCmd 在非 Windows 平台无需隐藏窗口。
func prepCmd(cmd *exec.Cmd) {}

// listDrives 在非 Windows 平台返回空（仅用于开发自测）。
func listDrives() []string { return nil }

// runGUI 在非 Windows 平台不可用，返回 false 让 main 走控制台菜单。
func runGUI() bool { return false }

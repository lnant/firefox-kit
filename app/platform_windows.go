//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCP   = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOut  = kernel32.NewProc("SetConsoleOutputCP")
	procGetDriveType   = kernel32.NewProc("GetDriveTypeW")
	procGetLogicalDrvs = kernel32.NewProc("GetLogicalDrives")
)

// setupConsole 把控制台切到 UTF-8，保证中文与 ✓/✘ 正常显示。
func setupConsole() {
	procSetConsoleCP.Call(65001)
	procSetConsoleOut.Call(65001)
}

// prepCmd 让子进程不弹黑窗（Xray 在后台静默运行）。
func prepCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// listDrives 列出当前可用盘符，并标注可移动盘。
func listDrives() []string {
	mask, _, _ := procGetLogicalDrvs.Call()
	out := []string{}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A' + i))
		root := letter + ":\\"
		p, _ := syscall.UTF16PtrFromString(root)
		t, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(p)))
		kind := ""
		switch t {
		case 2:
			kind = "（可移动/U盘）"
		case 3:
			kind = "（本地硬盘）"
		case 4:
			kind = "（网络驱动器）"
		case 5:
			kind = "（光盘）"
		}
		out = append(out, fmt.Sprintf("%s: %s", letter, kind))
	}
	return out
}

package main

// 运行控制：目录约定、浏览器配置写出、sing-box 与 Firefox 的启停、
// 异常退出后的残留自检恢复。
//
// 目录约定：
//   <工具目录>/nodes.txt、node.txt、subs.txt —— 节点库/当前节点/订阅
//   <工具目录>/Surf/core/sing-box            —— 内核（外置）
//   <工具目录>/Surf/Firefox/firefox          —— 专用浏览器（或用系统已装的）
//   <工具目录>/Surf/ff-data                  —— 专用浏览器数据（独立，永不被更新触碰）
//   <工具目录>/Surf/config.json              —— 当前生成的配置（.prev 是上一份）

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		wd, _ := os.Getwd()
		return wd
	}
	return filepath.Dir(p)
}

func binName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func surfDir(root string) string     { return filepath.Join(root, "Surf") }
func configPath(root string) string  { return filepath.Join(surfDir(root), "config.json") }
func profileDir(root string) string  { return filepath.Join(surfDir(root), "ff-data") }
func pidPath(root string) string     { return filepath.Join(surfDir(root), "singbox.pid") }
func firefoxName() string            { return binName("firefox") }

// FirefoxPath 找专用 Firefox：优先工具包内的，其次系统已安装的。
func FirefoxPath(root string) string {
	cands := []string{
		filepath.Join(surfDir(root), "Firefox", firefoxName()),
		filepath.Join(root, "Firefox", firefoxName()),
	}
	if runtime.GOOS == "windows" {
		cands = append(cands,
			`C:\Program Files\Mozilla Firefox\firefox.exe`,
			`C:\Program Files (x86)\Mozilla Firefox\firefox.exe`,
		)
	} else {
		cands = append(cands, "/usr/bin/firefox", "/usr/local/bin/firefox")
	}
	for _, c := range cands {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

func FirefoxReady(root string) bool { return FirefoxPath(root) != "" }

// firefoxPolicyValues 是写给工具包专用 Firefox 的企业策略：关掉它自带的
// 应用更新、后台更新与默认浏览器代理。这三样会在 Windows 里注册计划任务，
// 杀毒软件常把这类任务算作「可疑启动项」；浏览器的更新由工具包自己的
// 按钮（准备浏览器）负责，不靠它自更新。
var firefoxPolicyValues = map[string]any{
	"DisableAppUpdate":           true,
	"BackgroundAppUpdate":        false,
	"DisableDefaultBrowserAgent": true,
}

// EnsureFirefoxPolicies 把策略写入专用 Firefox 程序目录下的
// distribution/policies.json（Firefox 官方的企业策略机制，启动时读取）。
// 只对工具目录内的 Firefox 副本动手；系统已装的 Firefox 一律不碰。
// 已有 policies.json 时合并：保留其他策略，只覆写本程序负责的三项。
// 内容已一致时不重复写；任何失败都静默放弃，不阻断浏览器启动。
func EnsureFirefoxPolicies(root, ffPath string) {
	dir := filepath.Dir(ffPath)
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return // 工具目录之外（系统安装版），不碰
	}
	target := filepath.Join(dir, "distribution", "policies.json")
	doc := map[string]any{}
	if b, err := os.ReadFile(target); err == nil {
		var existing map[string]any
		if json.Unmarshal(b, &existing) == nil && existing != nil {
			doc = existing
		}
	}
	pol, _ := doc["policies"].(map[string]any)
	if pol == nil {
		pol = map[string]any{}
	}
	for k, v := range firefoxPolicyValues {
		pol[k] = v
	}
	doc["policies"] = pol
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	out = append(out, '\n')
	if cur, err := os.ReadFile(target); err == nil && string(cur) == string(out) {
		return // 已落好且内容一致
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(target, out, 0o644)
}

func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	prepCmd(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// WriteProfile 按节点分支写专用浏览器的 user.js（启动前调用，浏览器未运行时生效）。
func WriteProfile(root string, n *Node) error {
	dir := profileDir(root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var proxy strings.Builder
	proxy.WriteString("user_pref(\"network.proxy.type\", 1);\n")
	switch {
	case n.Branch() == BranchDirect && n.Proto == "http":
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.http\", %q);\n", n.Address)
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.http_port\", %d);\n", n.Port)
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.ssl\", %q);\n", n.Address)
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.ssl_port\", %d);\n", n.Port)
		proxy.WriteString("user_pref(\"network.proxy.share_proxy_settings\", true);\n")
	case n.Branch() == BranchDirect: // SOCKS 直连远端
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.socks\", %q);\n", n.Address)
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.socks_port\", %d);\n", n.Port)
		proxy.WriteString("user_pref(\"network.proxy.socks_version\", 5);\n")
		proxy.WriteString("user_pref(\"network.proxy.socks_remote_dns\", true);\n")
	default: // B/C：连本地 sing-box 入口
		proxy.WriteString("user_pref(\"network.proxy.socks\", \"127.0.0.1\");\n")
		fmt.Fprintf(&proxy, "user_pref(\"network.proxy.socks_port\", %d);\n", LocalPort)
		proxy.WriteString("user_pref(\"network.proxy.socks_version\", 5);\n")
		proxy.WriteString("user_pref(\"network.proxy.socks_remote_dns\", true);\n")
	}
	common := `user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");
user_pref("media.peerconnection.enabled", false);
user_pref("network.trr.mode", 5);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("signon.rememberSignons", true);
`
	content := "// foxkit 自动生成：代理指向与隐私设置。手改会在下次启动时被覆盖。\n" + proxy.String() + common
	return os.WriteFile(filepath.Join(dir, "user.js"), []byte(content), 0o644)
}

// Runner 管理本程序拉起的 sing-box 与 Firefox 进程。
type Runner struct {
	core    *exec.Cmd
	browser *exec.Cmd
	Running bool
}

func NewRunner() *Runner { return &Runner{} }

// Start 按当前节点启动：B/C 先生成配置→自检→起内核→等端口；再写浏览器配置→开浏览器。
// 任一步失败都会回滚（停掉已起的内核、保留上一份配置），不留半截状态。
func (r *Runner) Start(root string, n *Node) error {
	if r.Running {
		return fmt.Errorf("已经在运行了")
	}
	if n.Branch() != BranchDirect {
		if !KernelReady(root) {
			return fmt.Errorf("这个节点需要内核，先准备内核")
		}
		cfg := configPath(root)
		if err := WriteConfig(n, cfg, LocalPort); err != nil {
			return err
		}
		if checked, err := CheckConfig(singboxPath(root), cfg); checked && err != nil {
			// 自检没过：退回上一份配置并报错，不带病启动
			if fileExists(cfg + ".prev") {
				_ = copyFileSimple(cfg+".prev", cfg)
			}
			return err
		}
		cmd := exec.Command(singboxPath(root), "run", "-c", cfg)
		cmd.Dir = surfDir(root)
		prepCmd(cmd)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("内核启动失败：%v", err)
		}
		r.core = cmd
		_ = os.WriteFile(pidPath(root), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
		if !waitPort(LocalPort, 6*time.Second) {
			r.stopCore()
			return fmt.Errorf("内核没有正常起来（本地端口未就绪），换一个节点或稍后再试")
		}
	}
	if err := WriteProfile(root, n); err != nil {
		r.stopCore()
		return fmt.Errorf("浏览器配置写不进去：%v", err)
	}
	ff := FirefoxPath(root)
	if ff == "" {
		r.stopCore()
		return fmt.Errorf("找不到 Firefox 浏览器")
	}
	EnsureFirefoxPolicies(root, ff) // 落企业策略：关自带更新/后台任务/默认浏览器代理
	fc := exec.Command(ff, "-profile", profileDir(root), "-no-remote")
	prepCmd(fc)
	if err := fc.Start(); err != nil {
		r.stopCore()
		return fmt.Errorf("浏览器启动失败：%v", err)
	}
	r.browser = fc
	r.Running = true
	return nil
}

func (r *Runner) stopCore() {
	if r.core != nil && r.core.Process != nil {
		_ = r.core.Process.Kill()
		_, _ = r.core.Process.Wait()
		r.core = nil
	}
}

// Stop 停内核（浏览器由用户自己关：它会随之断网，界面上有说明）。
func (r *Runner) Stop(root string) {
	r.stopCore()
	_ = os.Remove(pidPath(root))
	r.Running = false
}

// RecoverStale 启动时自检：上次异常退出若留下孤儿内核进程（pid 文件还在、
// 本地端口还被占），就清掉它，恢复到干净的未运行状态。返回是否清理过。
func RecoverStale(root string) bool {
	b, err := os.ReadFile(pidPath(root))
	if err != nil {
		return false
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	cleaned := false
	if pid > 0 {
		if proc, err := os.FindProcess(pid); err == nil {
			// 只在本地端口确实被占用时动手，避免误伤同 pid 的无关进程
			if waitPort(LocalPort, 300*time.Millisecond) {
				_ = proc.Kill()
				cleaned = true
			}
		}
	}
	_ = os.Remove(pidPath(root))
	return cleaned
}

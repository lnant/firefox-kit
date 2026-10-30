package main

// foxkit（sing-box 内核版）入口。
//
// Windows 双击走图形界面；带参数或非 Windows 走控制台。
//   foxkit -selftest    跑内置自检（不联网）后退出，退出码 0=全过
//   foxkit -console     强制控制台菜单
//   foxkit -version     打印版本

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

const AppVersion = "1.0.1"

var logFn = func(s string) { fmt.Println(s) }

func pln(s string)               { logFn(s) }
func pf(format string, a ...any) { logFn(fmt.Sprintf(format, a...)) }

func main() {
	setupConsole()
	args := os.Args[1:]
	for _, a := range args {
		switch a {
		case "-version", "--version", "version":
			fmt.Println("foxkit", AppVersion)
			return
		case "-selftest", "--selftest", "selftest":
			os.Exit(selftestMain())
		}
	}
	forceConsole := false
	for _, a := range args {
		if a == "-console" || a == "--console" || a == "console" {
			forceConsole = true
		}
	}
	if !forceConsole && runGUI() {
		return
	}
	consoleMain()
}

func selftestMain() int {
	results := RunSelfChecks()
	pass, fail := 0, 0
	for _, r := range results {
		if r.OK {
			pass++
			fmt.Printf("✓ %s%s\n", r.Name, detailSuffix(r.Detail))
		} else {
			fail++
			fmt.Printf("✘ %s%s\n", r.Name, detailSuffix(r.Detail))
		}
	}
	fmt.Printf("自检完成：%d 过 / %d 败\n", pass, fail)
	if fail > 0 {
		return 1
	}
	return 0
}

func detailSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " — " + d
}

// ---------------- 控制台菜单（脚本/调试用，逻辑与 GUI 共用同一套函数） ----------------

type consoleApp struct {
	root    string
	entries []*LibEntry
	current *LibEntry
	runner  *Runner
	reader  *bufio.Reader
}

func consoleMain() {
	root := exeDir()
	app := &consoleApp{root: root, runner: NewRunner(), reader: bufio.NewReader(os.Stdin)}
	app.entries = LoadLibrary(root)
	if link := ReadCurrentLink(root); link != "" {
		for _, e := range app.entries {
			if e.Link == link {
				app.current = e
			}
		}
	}
	if RecoverStale(root) {
		pln("（已清理上次异常退出留下的内核进程）")
	}
	if AdoptLooseKernel(root) {
		pln("（已把放在工具文件夹根目录的 sing-box 内核收进 Surf/core）")
	}
	pf("foxkit %s（sing-box 版）控制台", AppVersion)
	for {
		app.showStatus()
		pln("1 导入节点（粘贴）  2 订阅导入  3 选择当前节点  4 测试当前  5 测试全部")
		pln("6 准备/更新内核    7 启动浏览器  8 停止        9 删除当前节点  0 退出")
		choice := app.prompt("请选择：")
		switch choice {
		case "1":
			app.doImport()
		case "2":
			app.doSub()
		case "3":
			app.doSelect()
		case "4":
			app.doTestOne()
		case "5":
			app.doTestAll()
		case "6":
			app.doKernel()
		case "7":
			app.doStart()
		case "8":
			app.runner.Stop(root)
			pln("✓ 已停止内核（浏览器请自行关闭，它会随之断网）")
		case "9":
			app.doDeleteCurrent()
		case "0", "":
			if choice == "0" {
				app.runner.Stop(root)
				pln("再见。")
				return
			}
		}
	}
}

func (a *consoleApp) state() KitState {
	s := KitState{
		NodeCount:    len(a.entries),
		KernelReady:  KernelReady(a.root),
		FirefoxReady: FirefoxReady(a.root),
		Running:      a.runner.Running,
	}
	if a.current != nil {
		s.HasCurrent = true
		s.CurrentBranch = a.current.Node.Branch()
	}
	return s
}

func (a *consoleApp) showStatus() {
	act := ComputeActions(a.state())
	pln("———")
	pf("状态：%s", act.StatusText)
	if a.current != nil {
		pf("当前节点：%s", a.current.Display())
	}
	if v := KernelVersion(a.root); v != "" {
		pf("内核：sing-box %s", v)
	}
}

func (a *consoleApp) prompt(label string) string {
	fmt.Print(label)
	line, _ := a.reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func (a *consoleApp) doImport() {
	pln("把节点内容粘贴进来（可以多条、可以整段订阅原文），输入空行结束：")
	var lines []string
	for {
		line := a.prompt("")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	rep := ImportText(a.entries, strings.Join(lines, "\n"))
	a.entries = rep.Entries
	if rep.Added > 0 {
		_ = SaveLibrary(a.root, a.entries)
	}
	pln("✓ " + rep.Summary())
	for _, f := range rep.Failed {
		pf("  ✘ %s —— %s", f.Text, f.Reason)
	}
}

func (a *consoleApp) doSub() {
	u := a.prompt("订阅地址：")
	if u == "" {
		return
	}
	links, err := FetchSubscription(u)
	if err != nil {
		pln("✘ " + err.Error())
		return
	}
	rep := ImportLinks(a.entries, links)
	a.entries = rep.Entries
	if rep.Added > 0 {
		_ = SaveLibrary(a.root, a.entries)
		SaveSub(a.root, u)
	}
	pln("✓ " + rep.Summary())
}

func (a *consoleApp) doSelect() {
	act := ComputeActions(a.state())
	if !act.CanSelect {
		pln("✘ " + act.SelectHint)
		return
	}
	for i, e := range a.entries {
		mark := "  "
		if a.current == e {
			mark = "→ "
		}
		pf("%s%d. %s", mark, i+1, e.Display())
	}
	sel := a.prompt("序号（回车取消）：")
	if sel == "" {
		pln("已取消，选择未变。")
		return
	}
	var idx int
	if _, err := fmt.Sscanf(sel, "%d", &idx); err != nil || idx < 1 || idx > len(a.entries) {
		pln("✘ 序号不对，选择未变。")
		return
	}
	a.current = a.entries[idx-1]
	_ = SaveCurrentLink(a.root, a.current.Link)
	pf("✓ 当前节点：%s", a.current.Display())
}

func (a *consoleApp) doTestOne() {
	act := ComputeActions(a.state())
	if !act.CanTestOne {
		pln("✘ " + act.TestOneHint)
		return
	}
	pln("正在测试…")
	r := TestNode(a.root, a.current, singboxPath(a.root))
	a.current.Test = r.Display()
	if r.OK {
		pf("✓ %s", r.Display())
	} else {
		pf("✘ %s", r.Display())
	}
}

func (a *consoleApp) doTestAll() {
	act := ComputeActions(a.state())
	if !act.CanTestAll {
		pln("✘ " + act.TestAllHint)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pln("正在逐个测试（顺序进行）…")
	TestAll(ctx, a.root, a.entries, singboxPath(a.root), func(done, total int, e *LibEntry, r TestResult) {
		pf("  (%d/%d) %s —— %s", done, total, e.Node.DisplayName(), r.Display())
	})
	pln("✓ 测试完成")
}

func (a *consoleApp) doKernel() {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	pln("正在从 sing-box 官方 GitHub 下载内核…")
	err := DownloadKernel(ctx, a.root, func(pct int) {
		if pct >= 0 {
			fmt.Printf("\r下载进度 %d%%", pct)
		}
	})
	fmt.Println()
	if err != nil {
		pln("✘ " + err.Error())
		return
	}
	pf("✓ 内核就绪：sing-box %s", KernelVersion(a.root))
}

func (a *consoleApp) doStart() {
	act := ComputeActions(a.state())
	if !act.CanStart {
		pln("✘ " + act.StartHint)
		return
	}
	if err := a.runner.Start(a.root, a.current.Node); err != nil {
		pln("✘ " + err.Error())
		return
	}
	pln("✓ 已启动：浏览器已打开。停止请选 8（会断开浏览器的网络）。")
}

func (a *consoleApp) doDeleteCurrent() {
	act := ComputeActions(a.state())
	if !act.CanDeleteCurrent {
		pln("✘ 当前没有可删的节点，或正在运行。")
		return
	}
	if a.prompt("确定删除当前节点？(y/N)：") != "y" {
		pln("已取消。")
		return
	}
	var kept []*LibEntry
	for _, e := range a.entries {
		if e != a.current {
			kept = append(kept, e)
		}
	}
	a.entries = kept
	a.current = nil
	_ = SaveLibrary(a.root, a.entries)
	_ = os.Remove(nodePath(a.root))
	pln("✓ 已删除。")
}

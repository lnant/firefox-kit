//go:build windows

package main

// 图形界面（Windows）。设计口径（与控制台共用同一套逻辑函数）：
//   主线就四步：导入 → 选中 → 测试（可选） → 启动
//   按钮能不能点、为什么不能点，全部由 ComputeActions 统一算，
//   置灰的按钮旁边常驻一行小字说明原因。
//   反馈只说人话：成功报数字、进行中给进度、失败给原因和下一步。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

var (
	guiMW        *walk.MainWindow
	guiStatusDot *walk.Label
	guiNodeLabel *walk.Label
	guiHintLabel *walk.Label
	guiList      *walk.ListBox
	guiModel     *nodeListModel
	guiImportBox *walk.TextEdit
	guiLogBox    *walk.TextEdit
	guiProgress  *walk.ProgressBar

	btnSetCurrent *walk.PushButton
	btnTestOne    *walk.PushButton
	btnDelete     *walk.PushButton
	btnRename     *walk.PushButton
	btnImport     *walk.PushButton
	btnSub        *walk.PushButton
	btnTestAll    *walk.PushButton
	btnStart      *walk.PushButton
	btnStop       *walk.PushButton
	btnKernel     *walk.PushButton
	btnCancel     *walk.PushButton
	btnFirefox    *walk.PushButton
	btnUpdate     *walk.PushButton
	btnFolder     *walk.PushButton

	colorOK   = walk.RGB(0x1D, 0x8A, 0x3A)
	colorBad  = walk.RGB(0xC0, 0x39, 0x2B)
	colorIdle = walk.RGB(0x66, 0x66, 0x66)
	colorBusy = walk.RGB(0x1F, 0x5C, 0xB8)
	accent    = walk.RGB(0x2F, 0x7F, 0xE0)
)

type guiApp struct {
	mu        sync.Mutex
	root      string
	entries   []*LibEntry
	current   *LibEntry
	runner    *Runner
	busy      string
	cancelFn  context.CancelFunc
	sel       int  // 列表里选中的序号，自己记，不读原生控件（刷新重置列表会把原生选择冲掉）
	restoring bool // 正在恢复选择时，忽略列表控件自己发出的序号变化事件
}

var g *guiApp

type nodeListModel struct {
	walk.ListModelBase
	items []string
}

func (m *nodeListModel) ItemCount() int  { return len(m.items) }
func (m *nodeListModel) Value(i int) any { return m.items[i] }

// guiSync 只是把函数排队到稍后的 UI 消息循环里执行，并不会等它执行完。
// 因此它只能用于日志、刷新、进度等不取返回值的更新；按钮事件本身已经在
// UI 线程里，读取控件值、弹确认框时必须直接调用，不能经过 guiSync，
// 否则会出现“控件里明明有内容、程序却读到空”的竞态。
func guiSync(f func()) {
	if guiMW != nil {
		guiMW.Synchronize(f)
	}
}

func guiLog(s string) {
	guiSync(func() {
		if guiLogBox != nil {
			guiLogBox.AppendText(s + "\r\n")
		}
	})
}

func (a *guiApp) selected() *LibEntry {
	// 选择记在 a.sel 里（由列表的序号变化事件在 UI 线程更新），不读原生控件：
	// 列表每次重置，原生选择都可能被清掉，读它会出现“行明明蓝着、程序却说没选”。
	if a.sel < 0 || a.sel >= len(a.entries) {
		return nil
	}
	return a.entries[a.sel]
}

func (a *guiApp) state() KitState {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := KitState{
		NodeCount:    len(a.entries),
		KernelReady:  KernelReady(a.root),
		FirefoxReady: FirefoxReady(a.root),
		Running:      a.runner.Running,
		Busy:         a.busy,
	}
	if a.current != nil {
		s.HasCurrent = true
		s.CurrentBranch = a.current.Node.Branch()
	}
	return s
}

// guiRefresh 按状态机统一刷新：列表、状态栏、所有按钮的可用性与提示。
func guiRefresh() {
	if g == nil {
		return
	}
	// 用户把内核文件直接放在工具根目录时，先收编进 Surf/core 再算状态。
	AdoptLooseKernel(g.root)
	act := ComputeActions(g.state())
	guiSync(func() {
		// 列表：内容没变就不重置——重置会清掉原生选择，恢复又靠不住，
		// 曾导致“行还蓝着、按钮却全是灰的”。
		items := make([]string, 0, len(g.entries))
		for _, e := range g.entries {
			prefix := ""
			if e == g.current {
				prefix = "▶ 当前 · "
			}
			items = append(items, prefix+e.Display())
		}
		if guiModel != nil {
			changed := len(items) != len(guiModel.items)
			if !changed {
				for i := range items {
					if items[i] != guiModel.items[i] {
						changed = true
						break
					}
				}
			}
			if changed {
				g.restoring = true
				guiModel.items = items
				guiModel.PublishItemsReset()
				g.restoring = false
				if guiList != nil && g.sel >= 0 && g.sel < len(items) && guiList.CurrentIndex() != g.sel {
					_ = guiList.SetCurrentIndex(g.sel)
				}
			}
		}
		selEntry := g.selected()
		// 状态栏
		if guiNodeLabel != nil {
			if g.current != nil {
				_ = guiNodeLabel.SetText(g.current.Display())
			} else {
				_ = guiNodeLabel.SetText("（还没有选中的节点）")
			}
		}
		if guiStatusDot != nil {
			_ = guiStatusDot.SetText("● " + act.StatusText)
			switch {
			case g.runner.Running:
				guiStatusDot.SetTextColor(colorOK)
			case g.busy != "":
				guiStatusDot.SetTextColor(colorBusy)
			case len(g.entries) == 0:
				guiStatusDot.SetTextColor(colorBad)
			default:
				guiStatusDot.SetTextColor(colorIdle)
			}
		}
		// 提示行：优先显示「启动为什么点不了」，其次是测试/切换的原因
		if guiHintLabel != nil {
			hint := act.StartHint
			if hint == "" {
				hint = act.TestOneHint
			}
			if hint == "" {
				hint = act.SelectHint
			}
			_ = guiHintLabel.SetText(hint)
		}
		setEnabled(btnSetCurrent, act.CanSelect && selEntry != nil)
		setEnabled(btnTestOne, act.CanTestOne && selEntry != nil)
		setEnabled(btnDelete, selEntry != nil && !g.runner.Running && g.busy == "")
		setEnabled(btnRename, selEntry != nil && g.busy == "")
		setEnabled(btnImport, g.busy == "")
		setEnabled(btnSub, act.CanFetchSub)
		setEnabled(btnTestAll, act.CanTestAll)
		setEnabled(btnStart, act.CanStart)
		setEnabled(btnStop, act.CanStop)
		setEnabled(btnKernel, act.CanPrepareKernel || act.CanUpdateKernel)
		if btnKernel != nil {
			if KernelReady(g.root) {
				_ = btnKernel.SetText("更新内核")
			} else {
				_ = btnKernel.SetText("准备内核")
			}
		}
		// 「准备浏览器」是把已装 Firefox 复制进工具包做便携用：本机装了 Firefox
		// 时也得能点，否则在装了 Firefox 的电脑上组装 U 盘时反而没法复制。
		setEnabled(btnFirefox, g.busy == "" && !g.runner.Running)
		setEnabled(btnUpdate, act.CanUpdateKernel)
		setEnabled(btnCancel, g.busy == "testing" || g.busy == "downloading")
		if guiProgress != nil && g.busy == "" {
			guiProgress.SetRange(0, 100)
			guiProgress.SetValue(0)
		}
	})
}

// guiSetProgress 从后台 goroutine 更新进度条（0-100）。
func guiSetProgress(pct int) {
	guiSync(func() {
		if guiProgress != nil {
			guiProgress.SetRange(0, 100)
			guiProgress.SetValue(pct)
		}
	})
}

func setEnabled(b *walk.PushButton, on bool) {
	if b != nil {
		b.SetEnabled(on)
	}
}

func (a *guiApp) setBusy(b string, cancel context.CancelFunc) {
	a.mu.Lock()
	a.busy = b
	a.cancelFn = cancel
	a.mu.Unlock()
	guiRefresh()
}

func (a *guiApp) saveLib() {
	if err := SaveLibrary(a.root, a.entries); err != nil {
		guiLog("✘ 节点库保存失败：" + err.Error())
	}
}

func msgInfo(title, text string) {
	guiSync(func() { walk.MsgBox(guiMW, title, text, walk.MsgBoxOK|walk.MsgBoxIconInformation) })
}
func msgError(title, text string) {
	guiSync(func() { walk.MsgBox(guiMW, title, text, walk.MsgBoxOK|walk.MsgBoxIconError) })
}
func askYesNo(title, text string) bool {
	// 只从按钮事件里调用，调用时已经在 UI 线程。若再经 guiSync 排队又立刻
	// 等结果，消息循环会被当前事件占住，确认框反而出不来。
	r := walk.MsgBox(guiMW, title, text, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion)
	return r == walk.DlgCmdYes
}

// promptText 弹一个带输入框的小对话框（订阅地址、改名用）。
func promptText(title, label, initial string) (string, bool) {
	var dlg *walk.Dialog
	var edit *walk.LineEdit
	var okBtn, cancelBtn *walk.PushButton
	result := ""
	accepted := false
	_, _ = Dialog{
		AssignTo:      &dlg,
		Title:         title,
		DefaultButton: &okBtn,
		CancelButton:  &cancelBtn,
		MinSize:       Size{Width: 420, Height: 140},
		Layout:        VBox{Spacing: 8},
		Children: []Widget{
			Label{Text: label},
			LineEdit{AssignTo: &edit, Text: initial},
			Composite{
				Layout: HBox{Spacing: 6},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &okBtn, Text: "确定", OnClicked: func() {
						result = strings.TrimSpace(edit.Text())
						accepted = true
						dlg.Accept()
					}},
					PushButton{AssignTo: &cancelBtn, Text: "取消", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}.Run(guiMW)
	return result, accepted
}

// ---------------- 各按钮动作 ----------------

func guiDoImport() {
	// 按钮事件就在 UI 线程里，直接取粘贴框内容；经 guiSync 排队会读到空。
	text := guiImportBox.Text()
	if strings.TrimSpace(text) == "" {
		msgInfo("导入节点", "先把节点内容粘贴到上面的框里，再点导入。")
		return
	}
	rep := ImportText(g.entries, text)
	g.entries = rep.Entries
	if rep.Added > 0 {
		g.saveLib()
	}
	// 有节点时默认选中第一条，下一步的按钮直接就能点，少绕一步。
	if len(g.entries) > 0 && g.sel < 0 {
		g.sel = 0
	}
	guiLog("导入结果：" + rep.Summary())
	for _, f := range rep.Failed {
		guiLog("  ✘ " + f.Text + " —— " + f.Reason)
	}
	// 失败的条目留在框里，改好了可以再点导入，不会丢
	if len(rep.Failed) > 0 {
		var left []string
		for _, f := range rep.Failed {
			left = append(left, f.Text)
		}
		_ = guiImportBox.SetText(strings.Join(left, "\r\n"))
	} else {
		_ = guiImportBox.SetText("")
	}
	if len(rep.Failed) > 0 {
		msgInfo("导入完成", rep.Summary()+"\n失败的条目还留在粘贴框里，改好后可以再导入。")
	}
	guiRefresh()
}

func guiDoSub() {
	u, ok := promptText("订阅导入", "把订阅地址粘贴到这里：", "")
	if !ok || u == "" {
		return
	}
	g.setBusy("downloading", nil)
	go func() {
		defer g.setBusy("", nil)
		links, err := FetchSubscription(u)
		if err != nil {
			guiLog("✘ 订阅拉取失败：" + err.Error())
			msgError("订阅导入", err.Error())
			return
		}
		rep := ImportLinks(g.entries, links)
		g.entries = rep.Entries
		if rep.Added > 0 {
			g.saveLib()
			SaveSub(g.root, u)
		}
		guiLog("订阅导入：" + rep.Summary())
		msgInfo("订阅导入", rep.Summary())
	}()
}

func guiDoSetCurrent() {
	e := g.selected()
	if e == nil {
		return
	}
	g.current = e
	_ = SaveCurrentLink(g.root, e.Link)
	guiLog("✓ 当前节点：" + e.Display())
	guiRefresh()
}

func guiDoDelete() {
	e := g.selected()
	if e == nil {
		return
	}
	if e == g.current && g.runner.Running {
		msgInfo("删除节点", "这个节点正在运行，先停止再删。")
		return
	}
	if !askYesNo("删除节点", "确定删除「"+e.Node.DisplayName()+"」吗？") {
		return
	}
	var kept []*LibEntry
	for _, x := range g.entries {
		if x != e {
			kept = append(kept, x)
		}
	}
	g.entries = kept
	if g.current == e {
		g.current = nil
		_ = os.Remove(nodePath(g.root))
	}
	if g.sel >= len(g.entries) {
		g.sel = len(g.entries) - 1
	}
	g.saveLib()
	guiLog("✓ 已删除节点：" + e.Node.DisplayName())
	guiRefresh()
}

func guiDoRename() {
	e := g.selected()
	if e == nil {
		return
	}
	name, ok := promptText("改名", "给节点起个好认的名字：", e.Node.Name)
	if !ok {
		return
	}
	e.Node.Name = name
	// 名字只存在链接的 # 片段里：同步改链接本身，保证存盘后不丢
	base := e.Link
	if i := strings.Index(base, "#"); i >= 0 {
		base = base[:i]
	}
	if name != "" && !strings.HasPrefix(base, "vmess://") {
		e.Link = base + "#" + name
	}
	g.saveLib()
	guiRefresh()
}

func guiDoTestOne() {
	e := g.selected()
	if e == nil {
		return
	}
	act := ComputeActions(g.state())
	if !act.CanTestOne {
		msgInfo("测试", act.TestOneHint)
		return
	}
	g.setBusy("testing", nil)
	go func() {
		defer g.setBusy("", nil)
		guiLog("正在测试：" + e.Node.DisplayName())
		r := TestNode(g.root, e, singboxPath(g.root))
		e.Test = r.Display()
		if r.OK {
			guiLog("✓ " + e.Node.DisplayName() + " —— " + r.Display())
		} else {
			guiLog("✘ " + e.Node.DisplayName() + " —— " + r.Display())
		}
		guiRefresh()
	}()
}

func guiDoTestAll() {
	act := ComputeActions(g.state())
	if !act.CanTestAll {
		msgInfo("测试全部", act.TestAllHint)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.setBusy("testing", cancel)
	go func() {
		defer func() { g.setBusy("", nil); cancel() }()
		guiLog("开始逐个测试（顺序进行，可随时取消）…")
		TestAll(ctx, g.root, g.entries, singboxPath(g.root), func(done, total int, e *LibEntry, r TestResult) {
			guiLog(fmt.Sprintf("  (%d/%d) %s —— %s", done, total, e.Node.DisplayName(), r.Display()))
			guiSync(func() {
				if guiProgress != nil && total > 0 {
					guiProgress.SetRange(0, total)
					guiProgress.SetValue(done)
				}
			})
			guiRefresh()
		})
		guiLog("✓ 测试全部完成")
	}()
}

func guiDoKernel() {
	ctx, cancel := context.WithCancel(context.Background())
	g.setBusy("downloading", cancel)
	go func() {
		defer func() { g.setBusy("", nil); cancel() }()
		guiLog("正在从 sing-box 官方 GitHub 准备内核…")
		lastLog := -1
		err := DownloadKernel(ctx, g.root, func(pct int) {
			if pct >= 0 {
				guiSync(func() {
					if guiProgress != nil {
						guiProgress.SetRange(0, 100)
						guiProgress.SetValue(pct)
					}
				})
				if pct/20 != lastLog {
					lastLog = pct / 20
					guiLog(fmt.Sprintf("  下载进度 %d%%", pct))
				}
			}
		})
		if err != nil {
			if ctx.Err() != nil {
				guiLog("已取消内核下载。")
				return
			}
			guiLog("✘ 内核准备失败：" + err.Error())
			msgError("准备内核", err.Error())
			return
		}
		guiLog("✓ 内核就绪：sing-box " + KernelVersion(g.root))
	}()
}

func guiDoStart() {
	act := ComputeActions(g.state())
	if !act.CanStart {
		msgInfo("启动", act.StartHint)
		return
	}
	g.setBusy("starting", nil)
	go func() {
		defer g.setBusy("", nil)
		if err := g.runner.Start(g.root, g.current.Node); err != nil {
			guiLog("✘ 启动失败：" + err.Error())
			msgError("启动失败", err.Error())
			return
		}
		guiLog("✓ 已启动，浏览器已打开。")
		if g.current.Node.Branch() != BranchDirect {
			guiLog("  提醒：点「停止」会断开浏览器的网络，浏览器请自行关闭。")
		}
	}()
}

func guiDoStop() {
	g.runner.Stop(g.root)
	guiLog("✓ 已停止。")
	guiRefresh()
}

func guiDoCancel() {
	g.mu.Lock()
	cf := g.cancelFn
	g.mu.Unlock()
	if cf != nil {
		cf()
	}
}

func guiDoFirefox() {
	// 两种模式共存，效果一样（都把 Firefox 程序放进 Surf\Firefox）：
	// A）本机已装 Firefox → 直接复制它的程序目录；
	// B）没装也行 → 从工具文件夹里的官方完整版安装包提取，全程不安装。
	// 两种来源都在时，让用户自己选。
	dst := filepath.Join(surfDir(g.root), "Firefox")
	if fileExists(filepath.Join(dst, firefoxName())) {
		msgInfo("准备浏览器", "工具包里已经有 Firefox 了（Surf\\Firefox），不用再准备。")
		return
	}
	src := ""
	for _, c := range []string{`C:\Program Files\Mozilla Firefox`, `C:\Program Files (x86)\Mozilla Firefox`} {
		if st, err := os.Stat(filepath.Join(c, "firefox.exe")); err == nil && !st.IsDir() {
			src = c
			break
		}
	}
	installer := FindFirefoxInstaller(g.root)

	useInstaller := false
	switch {
	case src != "" && installer != "":
		// 都在：先问复制本机的，点「否」就改用安装包提取
		if askYesNo("准备浏览器", "两种来源都有：\n\n点「是」：复制本机已安装的 Firefox 进工具包；\n点「否」：改用工具文件夹里的安装包（"+filepath.Base(installer)+"）提取，不用安装。") {
			useInstaller = false
		} else {
			useInstaller = true
		}
	case installer != "":
		useInstaller = true
	case src != "":
		useInstaller = false
	default:
		msgInfo("准备浏览器", "现在还没有可用的 Firefox 来源。\n\n两个办法（任选其一）：\n1）把 Firefox 官方完整版安装包（Firefox Setup … .exe，约 90MB）放进工具文件夹，再点这个按钮，我直接从安装包提取，不用先安装；注意不要用几百 KB 的在线安装包；\n2）先装好 Firefox（官方版），再点这个按钮，我会把它的程序复制进工具包。\n\n浏览器的数据（登录、历史）存在 Surf\\ff-data，与程序分开，更新程序不会动它。")
		return
	}

	if useInstaller {
		if !askYesNo("准备浏览器", "从安装包 "+filepath.Base(installer)+" 提取 Firefox 到工具包（Surf\\Firefox）吗？\n全程不会安装，不写注册表；提取要花几分钟，窗口下方的进度条会一直走，跑完记录里会出结果。") {
			return
		}
		g.setBusy("updating", nil)
		go func() {
			defer g.setBusy("", nil)
			guiLog("正在从安装包提取 Firefox（要花几分钟，看进度条）…")
			if err := ExtractFirefoxFromInstaller(installer, g.root, guiSetProgress); err != nil {
				guiLog("✘ 从安装包提取 Firefox 失败：" + err.Error())
				msgError("准备浏览器", "提取失败："+err.Error())
				return
			}
			guiLog("✓ 浏览器已就绪（已从安装包提取进工具包）。")
		}()
		return
	}
	if !askYesNo("准备浏览器", "把本机的 Firefox 程序复制进工具包（Surf\\Firefox）吗？\n之后工具包就是便携的，插到哪台电脑都能用。") {
		return
	}
	g.setBusy("updating", nil)
	go func() {
		defer g.setBusy("", nil)
		guiLog("正在复制 Firefox 进工具包（看进度条）…")
		if err := copyDirProgress(src, dst, guiSetProgress); err != nil {
			guiLog("✘ 复制 Firefox 失败：" + err.Error())
			msgError("准备浏览器", "复制失败："+err.Error())
			return
		}
		guiLog("✓ 浏览器已就绪（程序已复制进工具包）。")
	}()
}

func guiDoUpdate() {
	// 「更新内核」与「准备内核」走同一条下载路径：新版验过才换，旧版留备份。
	guiDoKernel()
}

func guiDoFolder() {
	_ = exec.Command("explorer.exe", g.root).Start()
}

// ---------------- 主窗口 ----------------

func runGUI() bool {
	logFn = guiLog
	root := exeDir()
	g = &guiApp{root: root, runner: NewRunner(), sel: -1}
	g.entries = LoadLibrary(root)
	if link := ReadCurrentLink(root); link != "" {
		for i, e := range g.entries {
			if e.Link == link {
				g.current = e
				g.sel = i
			}
		}
	}
	if g.sel < 0 && len(g.entries) > 0 {
		g.sel = 0
	}
	guiModel = &nodeListModel{}

	font := Font{Family: "Microsoft YaHei UI", PointSize: 9}
	def := MainWindow{
		AssignTo: &guiMW,
		Title:    "foxkit " + AppVersion + " · 专用浏览器工具",
		MinSize:  Size{Width: 660, Height: 720},
		Size:     Size{Width: 700, Height: 780},
		Layout:   VBox{Spacing: 6, Margins: Margins{Left: 10, Top: 8, Right: 10, Bottom: 8}},
		Children: []Widget{
			Label{
				Text:      "foxkit 专用浏览器工具",
				Font:      Font{Family: "Microsoft YaHei UI", PointSize: 14, Bold: true},
				TextColor: accent,
			},
			Label{
				Text:      "支持 sing-box 的协议 · 节点与浏览器数据只存本地，不外传",
				Font:      font,
				TextColor: colorIdle,
			},
			GroupBox{
				Title:  "现在的状态",
				Layout: VBox{Spacing: 3},
				Children: []Widget{
					Label{AssignTo: &guiStatusDot, Text: "● …", Font: Font{Family: "Microsoft YaHei UI", PointSize: 10, Bold: true}},
					Label{AssignTo: &guiNodeLabel, Text: "（还没有选中的节点）", Font: font},
					Label{AssignTo: &guiHintLabel, Text: "", Font: font, TextColor: colorBad},
				},
			},
			GroupBox{
				Title:  "第 1 步 · 导入节点（粘贴到下面，点导入；只查格式，不测连通）",
				Layout: VBox{Spacing: 5},
				Children: []Widget{
					TextEdit{AssignTo: &guiImportBox, MaxLength: 0, VScroll: true},
					Composite{
						Layout: HBox{Spacing: 6},
						Children: []Widget{
							PushButton{AssignTo: &btnImport, Text: "导入", OnClicked: guiDoImport},
							PushButton{AssignTo: &btnSub, Text: "订阅导入", OnClicked: guiDoSub},
							HSpacer{},
							Label{Text: "导入后在下面列表里选节点", Font: font, TextColor: colorIdle},
						},
					},
				},
			},
			GroupBox{
				Title:  "第 2 步 · 节点库（选中一条，再设为当前）",
				Layout: VBox{Spacing: 5},
				Children: []Widget{
					ListBox{
						AssignTo:        &guiList,
						Model:           guiModel,
						OnItemActivated: guiDoSetCurrent,
						OnCurrentIndexChanged: func() {
							// 事件就在 UI 线程，直接读原生序号记下来；
							// 刷新恢复选择期间控件自己发的变化不算数。
							if g != nil && !g.restoring && guiList != nil {
								g.sel = guiList.CurrentIndex()
							}
							guiRefresh()
						},
					},
					Composite{
						Layout: HBox{Spacing: 6},
						Children: []Widget{
							PushButton{AssignTo: &btnSetCurrent, Text: "设为当前节点", OnClicked: guiDoSetCurrent},
							PushButton{AssignTo: &btnTestOne, Text: "测试选中", OnClicked: guiDoTestOne},
							PushButton{AssignTo: &btnTestAll, Text: "测试全部", OnClicked: guiDoTestAll},
							PushButton{AssignTo: &btnRename, Text: "改名", OnClicked: guiDoRename},
							PushButton{AssignTo: &btnDelete, Text: "删除", OnClicked: guiDoDelete},
						},
					},
				},
			},
			GroupBox{
				Title:  "第 3 步 · 启动（测试可选，测不通也会提醒但不拦着启动）",
				Layout: VBox{Spacing: 5},
				Children: []Widget{
					Composite{
						Layout: HBox{Spacing: 6},
						Children: []Widget{
							PushButton{AssignTo: &btnStart, Text: "▶ 启动浏览器", OnClicked: guiDoStart, Font: Font{Family: "Microsoft YaHei UI", PointSize: 10, Bold: true}},
							PushButton{AssignTo: &btnStop, Text: "■ 停止", OnClicked: guiDoStop},
							PushButton{AssignTo: &btnCancel, Text: "取消当前操作", OnClicked: guiDoCancel},
							HSpacer{},
							PushButton{AssignTo: &btnKernel, Text: "准备内核", OnClicked: guiDoKernel},
						},
					},
					ProgressBar{AssignTo: &guiProgress, MaxValue: 100},
				},
			},
			Composite{
				Layout: HBox{Spacing: 6},
				Children: []Widget{
					Label{Text: "工具：", Font: font, TextColor: colorIdle},
					PushButton{AssignTo: &btnFirefox, Text: "准备浏览器", OnClicked: guiDoFirefox},
					PushButton{AssignTo: &btnUpdate, Text: "更新内核", OnClicked: guiDoUpdate},
					PushButton{AssignTo: &btnFolder, Text: "打开工具文件夹", OnClicked: guiDoFolder},
					HSpacer{},
					Label{Text: "内核与浏览器都是外置组件，按需准备", Font: font, TextColor: colorIdle},
				},
			},
			GroupBox{
				Title:  "记录",
				Layout: VBox{Spacing: 3},
				Children: []Widget{
					TextEdit{AssignTo: &guiLogBox, ReadOnly: true, VScroll: true, MaxLength: 0},
				},
			},
		},
	}
	if err := def.Create(); err != nil {
		return false
	}
	guiMW.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if g != nil && g.runner != nil {
			g.runner.Stop(g.root)
		}
	})
	// 固定几个区域的高度，免得列表和日志互相挤没
	guiSync(func() {
		if guiImportBox != nil {
			_ = guiImportBox.SetMinMaxSize(walk.Size{Width: 0, Height: 56}, walk.Size{Width: 0, Height: 56})
		}
		if guiList != nil {
			_ = guiList.SetMinMaxSize(walk.Size{Width: 0, Height: 130}, walk.Size{Width: 0, Height: 130})
		}
		if guiLogBox != nil {
			_ = guiLogBox.SetMinMaxSize(walk.Size{Width: 0, Height: 110}, walk.Size{Width: 0, Height: 110})
		}
	})
	if RecoverStale(root) {
		guiLog("（已清理上次没正常退出留下的内核进程）")
	}
	if AdoptLooseKernel(root) {
		guiLog("（已把放在工具文件夹根目录的 sing-box 内核收进 Surf\\core）")
	}
	if v := KernelVersion(root); v != "" {
		guiLog("内核：sing-box " + v)
	} else {
		guiLog("内核还没准备：直连的 SOCKS 节点不需要内核；其他节点在启动前点「准备内核」。")
	}
	guiLog("流程：导入节点 → 在列表里选中并设为当前 →（可先测试）→ 启动浏览器。")
	guiRefresh()
	guiMW.Run()
	return true
}

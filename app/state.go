package main

// 界面状态机：所有按钮「能不能点、不能点是为什么」都由这里统一算，
// GUI 与控制台共用，保证内部逻辑只有一份、不打架。
//
// 硬前置（不满足就置灰并给原因）：
//   - 测试要先有选中的节点；测全部要有节点
//   - 启动要先选中节点；B/C 类节点要先备好内核；浏览器要先就位
//   - 运行中锁定：测试 / 删当前节点 / 更新内核不可用
// 运行中可就地生效（不拦，handler 里重启内核应用）：
//   - 切换当前节点、修改当前节点链接（限走内核的节点；涉及直连节点时
//     保存后提示重启浏览器才完全生效）
// 软性事项（只提醒、不拦路）：
//   - 测试没通过也能启动（测速点可能临时不准，不能把用户卡死）
//   - 导入、查看列表在任何状态下都可以（不碰运行状态）

type KitState struct {
	NodeCount      int
	HasCurrent     bool
	CurrentBranch  Branch // HasCurrent 为假时无意义
	HasSelected    bool
	SelectedBranch Branch // HasSelected 为假时无意义
	KernelReady    bool
	FirefoxReady   bool
	Running        bool
	Busy           string // "" / "downloading" / "testing" / "starting" / "updating"
}

type Actions struct {
	CanImport        bool
	CanSelect        bool
	CanTestOne       bool
	CanTestAll       bool
	CanStart         bool
	CanStop          bool
	CanPrepareKernel bool
	CanUpdateKernel  bool
	CanPrepareFirefox bool
	CanDeleteCurrent bool
	CanFetchSub      bool

	NeedKernel   bool   // 当前节点是否需要内核（B/C 类）
	TestOneHint  string // 置灰原因（可点时为空）
	TestAllHint  string
	StartHint    string
	SelectHint   string
	UpdateHint   string
	StatusText   string // 顶部状态栏一句话
}

func ComputeActions(s KitState) Actions {
	a := Actions{CanImport: true, CanFetchSub: s.Busy == "" && !s.Running}
	a.NeedKernel = s.HasCurrent && s.CurrentBranch != BranchDirect

	// 选中/切换（运行中也能切换，走内核的节点重启内核就地生效）
	switch {
	case s.NodeCount == 0:
		a.SelectHint = "先导入节点"
	case s.Busy != "":
		a.SelectHint = "正在处理，稍等一下"
	default:
		a.CanSelect = true
	}

	// 测试选中（按「选中的那条」算，不按当前节点）
	switch {
	case s.NodeCount == 0:
		a.TestOneHint = "先导入节点"
	case !s.HasSelected:
		a.TestOneHint = "先选一个节点"
	case s.Running:
		a.TestOneHint = "正在运行，先停止再测试"
	case s.Busy != "":
		a.TestOneHint = "正在处理，稍等一下"
	case s.SelectedBranch != BranchDirect && !s.KernelReady:
		a.TestOneHint = "这个节点测试要用到内核，先准备内核"
	default:
		a.CanTestOne = true
	}

	// 测试全部
	switch {
	case s.NodeCount == 0:
		a.TestAllHint = "先导入节点"
	case s.Running:
		a.TestAllHint = "正在运行，先停止再测试"
	case s.Busy != "":
		a.TestAllHint = "正在处理，稍等一下"
	case !s.KernelReady && s.HasCurrent && a.NeedKernel:
		// 库里可能混有直连节点；全部测试里需内核的会逐条提示，不整场拦
		a.CanTestAll = true
	default:
		a.CanTestAll = true
	}

	// 内核准备/更新：必须卡死在流程上——先有需要内核的当前节点，才谈得上准备内核。
	a.CanPrepareKernel = a.NeedKernel && !s.KernelReady && !s.Running && s.Busy == ""
	// 准备/更新浏览器同样卡死：先设了当前（活跃）节点才亮，顺序不许乱。
	a.CanPrepareFirefox = s.HasCurrent && !s.Running && s.Busy == ""
	switch {
	case s.Running:
		a.UpdateHint = "正在运行，先停止再更新内核"
	case s.Busy != "":
		a.UpdateHint = "正在处理，稍等一下"
	case !s.KernelReady:
		a.UpdateHint = "内核还没准备好"
	default:
		a.CanUpdateKernel = true
	}

	// 启动
	switch {
	case s.Running:
		a.StartHint = "已经在运行了"
	case s.NodeCount == 0:
		a.StartHint = "先导入节点"
	case !s.HasCurrent:
		a.StartHint = "先点「设为当前节点」把节点设为活跃，再准备内核和浏览器"
	case a.NeedKernel && !s.KernelReady:
		a.StartHint = "这个节点需要内核，先点「准备内核」"
	case !s.FirefoxReady:
		a.StartHint = "浏览器还没准备好，先在工具页准备浏览器"
	case s.Busy != "":
		a.StartHint = "正在处理，稍等一下"
	default:
		a.CanStart = true
	}

	a.CanStop = s.Running
	a.CanDeleteCurrent = s.HasCurrent && !s.Running && s.Busy == ""

	// 状态栏一句话
	switch {
	case s.Busy == "downloading":
		a.StatusText = "正在准备内核…"
	case s.Busy == "testing":
		a.StatusText = "正在测试…"
	case s.Busy == "starting":
		a.StatusText = "正在启动…"
	case s.Busy == "updating":
		a.StatusText = "正在更新…"
	case s.Running:
		a.StatusText = "运行中"
	case s.NodeCount == 0:
		a.StatusText = "还没有节点，先导入"
	case !s.HasCurrent:
		a.StatusText = "选一个节点就能开始"
	case a.NeedKernel && !s.KernelReady:
		a.StatusText = "当前节点需要内核，先准备内核"
	case !s.FirefoxReady:
		a.StatusText = "当前节点已就绪，还差浏览器"
	default:
		a.StatusText = "已就绪，可以启动"
	}
	return a
}

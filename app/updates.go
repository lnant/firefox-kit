package main

// 组件更新检测：浏览器（Firefox）与 sing-box 内核，本地版本对比官方最新版。
//
// 数据来源（都只问版本号，不下载任何东西）：
//   - Firefox 最新版：Mozilla 官方 product-details 接口的 LATEST_FIREFOX_VERSION。
//     本工具历来不下载 Firefox（靠复制本机已装的或从官方安装包提取），检测同理。
//   - sing-box 最新版：官方 GitHub releases/latest 的 tag，与「更新内核」同一来源。
//
// 本地版本：
//   - Firefox：读工具包里 Firefox 程序目录的 application.ini（[App] 的 Version=）。
//   - sing-box：复用 KernelVersion（跑 sing-box version）。
//
// “重大更新”看发布列车有没有变：Firefox 看第一段（159→160 是它每月一次的大版本）；
// sing-box 首段恒为 1、看前两段（1.14→1.15 是带协议变更的发布，1.14.4→1.14.5 只是小修）。
// 检测失败（没联网等）只标注、不拦路，不影响任何既有流程。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type UpdateLevel int

const (
	UpdateNone    UpdateLevel = iota // 已是最新
	UpdateMinor                      // 普通更新（小修小补）
	UpdateMajor                      // 重大更新（发布列车变了）
	UpdateUnknown                    // 没法判定（未准备 / 版本读不到 / 没查到最新版）
)

type ComponentUpdate struct {
	Key       string // "firefox" / "singbox"
	Name      string // 显示名
	Installed bool
	Current   string // 本地版本；读不到为空
	Latest    string // 官方最新版；没查到为空
	Level     UpdateLevel
	Note      string // 没查到最新版时的原因（简短）
}

// Line 状态区里的一行对比结果，说人话。
func (c ComponentUpdate) Line() string {
	switch {
	case !c.Installed:
		return c.Name + "：还没准备"
	case c.Current == "":
		return c.Name + "：已准备（本地版本读不到，没法对比）"
	case c.Latest == "":
		s := c.Name + "：当前 " + c.Current + "（最新版没查到"
		if c.Note != "" {
			s += "，" + c.Note
		}
		return s + "；不影响使用）"
	}
	switch c.Level {
	case UpdateMajor:
		return fmt.Sprintf("%s：当前 %s → 最新 %s ⚠ 重大更新，建议及时更新", c.Name, c.Current, c.Latest)
	case UpdateMinor:
		return fmt.Sprintf("%s：当前 %s → 最新 %s（有新版可用）", c.Name, c.Current, c.Latest)
	default:
		return fmt.Sprintf("%s：当前 %s ✓ 已是最新", c.Name, c.Current)
	}
}

// parseVersion 把 "1.14.4" 拆成 [1 14 4]；段内只取开头连续数字。
func parseVersion(s string) []int {
	s = strings.TrimSpace(strings.TrimPrefix(s, "v"))
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		digits := ""
		for _, r := range p {
			if r >= '0' && r <= '9' {
				digits += string(r)
			} else {
				break
			}
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

// compareVersions 逐段比大小：a<b 返回 -1，相等 0，a>b 返回 1。缺段按 0。
func compareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// updateLevel 判定更新级别：train 是“发布列车”占的段数（Firefox 1，sing-box 2）。
func updateLevel(cur, latest string, train int) UpdateLevel {
	if cur == "" || latest == "" {
		return UpdateUnknown
	}
	if compareVersions(latest, cur) <= 0 {
		return UpdateNone
	}
	pa, pb := parseVersion(cur), parseVersion(latest)
	for i := 0; i < train; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return UpdateMajor
		}
	}
	return UpdateMinor
}

// FirefoxLocalVersion 读工具包里 Firefox 的本地版本号。
// 找的目录与 runtime.go 找 firefox 本体的顺序一致：Surf/Firefox、工具根目录的 Firefox。
func FirefoxLocalVersion(root string) string {
	for _, dir := range []string{filepath.Join(surfDir(root), "Firefox"), filepath.Join(root, "Firefox")} {
		data, err := os.ReadFile(filepath.Join(dir, "application.ini"))
		if err != nil {
			continue
		}
		if v := parseAppIniVersion(string(data)); v != "" {
			return v
		}
	}
	return ""
}

// parseAppIniVersion 从 application.ini 文本里取 [App] 段的 Version=。
func parseAppIniVersion(text string) string {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		if section != "app" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), "Version") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func fetchJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "foxkit/"+AppVersion)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("连不上服务器：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("服务器返回 HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(dst)
}

// LatestFirefoxVersion 查 Mozilla 官方 product-details：正式版最新版本号。
func LatestFirefoxVersion(ctx context.Context) (string, error) {
	var pd struct {
		Latest string `json:"LATEST_FIREFOX_VERSION"`
	}
	if err := fetchJSON(ctx, "https://product-details.mozilla.org/1.0/firefox_versions.json", &pd); err != nil {
		return "", err
	}
	if pd.Latest == "" {
		return "", fmt.Errorf("官方数据里没有版本号")
	}
	return pd.Latest, nil
}

// LatestKernelVersion 只取 sing-box 最新版号（不挑安装包，检查更新用）。
func LatestKernelVersion(ctx context.Context) (string, error) {
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := fetchJSON(ctx, "https://api.github.com/repos/SagerNet/sing-box/releases/latest", &rel); err != nil {
		return "", err
	}
	ver := strings.TrimPrefix(rel.TagName, "v")
	if ver == "" {
		return "", fmt.Errorf("GitHub 数据里没有版本号")
	}
	return ver, nil
}

// CheckUpdates 检测两个组件，固定顺序返回（浏览器在前、内核在后）。
// 两个联网查询并行；任一失败只影响它自己的那一行。
func CheckUpdates(ctx context.Context, root string) []ComponentUpdate {
	ff := ComponentUpdate{Key: "firefox", Name: "浏览器（Firefox）", Installed: FirefoxReady(root)}
	if ff.Installed {
		ff.Current = FirefoxLocalVersion(root)
	}
	sb := ComponentUpdate{Key: "singbox", Name: "sing-box 内核", Installed: KernelReady(root)}
	if sb.Installed {
		sb.Current = KernelVersion(root)
	}

	var ffLatest, sbLatest string
	var ffErr, sbErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ffLatest, ffErr = LatestFirefoxVersion(ctx) }()
	go func() { defer wg.Done(); sbLatest, sbErr = LatestKernelVersion(ctx) }()
	wg.Wait()

	if ffErr != nil {
		ff.Note = "联网失败"
	} else {
		ff.Latest = ffLatest
	}
	if sbErr != nil {
		sb.Note = "联网失败"
	} else {
		sb.Latest = sbLatest
	}
	ff.Level = updateLevel(ff.Current, ff.Latest, 1)
	sb.Level = updateLevel(sb.Current, sb.Latest, 2)
	return []ComponentUpdate{ff, sb}
}

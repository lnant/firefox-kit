package main

// 导入格式校验（只把格式关，不测连通性——连通性是选中之后单独的事）。
//
// 反馈口径（简单明了）：
//   成功导入 X 条 / 重复跳过 Y 条 / 失败 Z 条（逐条说明是哪条、什么毛病）
// 失败的候选条目留在结果里，用户改完可以重试，不会一关对话框就丢。

import (
	"fmt"
	"strings"
)

type FailItem struct {
	Text   string // 出问题的那条（截短展示）
	Reason string // 一句人话原因
}

type ImportReport struct {
	Candidates int
	Added      int
	Duplicates int
	Failed     []FailItem
	Entries    []*LibEntry // 导入后的完整节点库
}

// Summary 一行版反馈，例如：
// 成功导入 5 条，重复跳过 1 条，2 条格式不对已跳过
func (r *ImportReport) Summary() string {
	s := "成功导入 " + itoa(r.Added) + " 条"
	if r.Duplicates > 0 {
		s += "，重复跳过 " + itoa(r.Duplicates) + " 条"
	}
	if len(r.Failed) > 0 {
		s += "，" + itoa(len(r.Failed)) + " 条格式不对已跳过"
	}
	if r.Candidates == 0 {
		s = "没有找到可导入的节点"
	}
	return s
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// ImportText 把一段粘贴文本并入现有节点库，返回逐项结果。
func ImportText(existing []*LibEntry, text string) *ImportReport {
	rep := &ImportReport{Entries: existing}
	seen := map[string]bool{}
	for _, e := range existing {
		seen[dedupKey(e.Node)] = true
	}
	for _, cand := range candidatesOf(text) {
		rep.Candidates++
		n, err := ParseLink(cand)
		if err != nil {
			rep.Failed = append(rep.Failed, FailItem{Text: shorten(cand), Reason: err.Error()})
			continue
		}
		k := dedupKey(n)
		if seen[k] {
			rep.Duplicates++
			continue
		}
		seen[k] = true
		rep.Entries = append(rep.Entries, &LibEntry{Link: cand, Node: n})
		rep.Added++
	}
	return rep
}

// ImportLinks 把已提取好的链接列表（订阅拉取的结果）并入节点库。
func ImportLinks(existing []*LibEntry, links []string) *ImportReport {
	return ImportText(existing, strings.Join(links, "\n"))
}

// ReplaceLink 把已有条目的链接换成新链接（第 2 步「修改链接」用）：
//   - 新链接先过格式校验，不过直接报错，原条目一点不动
//   - 与库里其他条目重复（dedupKey 相同）报错，原条目不动
//   - 保留条目现在的显示名：名字是用户在工具里认节点的依据，改链接不改名；
//     与「改名」同一口径——名字同步写回新链接的 # 片段（vmess 除外，
//     它的名字在链接体里，沿用改名的既有处理）
//   - 链接真变了才清掉旧的测试结果（那是测老链接得出的）
func ReplaceLink(entries []*LibEntry, e *LibEntry, newLink string) error {
	newLink = strings.TrimSpace(newLink)
	if newLink == "" {
		return fmt.Errorf("链接是空的")
	}
	if newLink == e.Link {
		return nil // 没改动
	}
	n, err := ParseLink(newLink)
	if err != nil {
		return err
	}
	k := dedupKey(n)
	for _, x := range entries {
		if x != e && dedupKey(x.Node) == k {
			return fmt.Errorf("和已有节点「%s」是同一个节点（重复了）", x.Node.DisplayName())
		}
	}
	if keep := e.Node.Name; keep != "" {
		n.Name = keep
		if !strings.HasPrefix(newLink, "vmess://") {
			base := newLink
			if i := strings.Index(base, "#"); i >= 0 {
				base = base[:i]
			}
			newLink = base + "#" + keep
		}
	}
	e.Link = newLink
	e.Node = n
	e.Test = ""
	return nil
}

// candidatesOf 从粘贴文本里挑出候选条目：
//   - 一行里夹着的链接（可能多条、可能混在文字中）逐条提取
//   - 没有链接但形似「地址:端口...」的整行，当作裸 SOCKS 候选交给解析器判
//   - 整段 base64（订阅原文）先解码再提取
//   - 普通网址行不当候选，但要给反馈（多半是把订阅地址粘错了地方）
func candidatesOf(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	// 整段 base64 且原文里看不到链接时，先解码
	if len(ExtractLinks(text)) == 0 {
		compact := strings.Join(strings.Fields(text), "")
		if !strings.Contains(compact, "://") && !strings.Contains(compact, ":") {
			if raw, err := b64Decode(compact); err == nil && len(raw) > 0 {
				text = string(raw)
			}
		}
	}
	out := []string{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if links := ExtractLinks(ln); len(links) > 0 {
			out = append(out, links...)
			continue
		}
		lower := strings.ToLower(ln)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			// 没有账号信息的网址：多半是订阅地址粘到节点导入里了
			out = append(out, ln) // 交给解析器，它会说明这不是节点
			continue
		}
		// 裸 SOCKS 候选：无空格、带冒号
		if !strings.ContainsAny(ln, " \t") && strings.Contains(ln, ":") {
			out = append(out, ln)
		}
		// 其余无法识别的行直接忽略（如说明文字）
	}
	return out
}

func shorten(s string) string {
	s = strings.TrimSpace(s)
	const max = 64
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max/2]) + "…" + string(r[len(r)-max/2+8:])
}

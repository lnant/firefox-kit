package main

// 导入格式校验（只把格式关，不测连通性——连通性是选中之后单独的事）。
//
// 反馈口径（简单明了）：
//   成功导入 X 条 / 重复跳过 Y 条 / 失败 Z 条（逐条说明是哪条、什么毛病）
// 失败的候选条目留在结果里，用户改完可以重试，不会一关对话框就丢。

import (
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

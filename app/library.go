package main

// 节点库存储（工具目录下的纯文本文件，一行一条，可手工查看）：
//   nodes.txt —— 节点库（所有已导入的节点链接）
//   subs.txt  —— 订阅地址（一行一个）
//   node.txt  —— 当前节点链接（沿用既有约定）
// 这些文件装的都是节点凭证，只存本地/U 盘，绝不外传。

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func libraryPath(root string) string { return filepath.Join(root, "nodes.txt") }
func subsPath(root string) string    { return filepath.Join(root, "subs.txt") }
func nodePath(root string) string    { return filepath.Join(root, "node.txt") }

type LibEntry struct {
	Link string
	Node *Node
	Test string // 最近一次连通测试结果（空 = 未测试）
}

func (e *LibEntry) Display() string {
	s := fmt.Sprintf("%s · %s", e.Node.DisplayName(), e.Node.Summary())
	if e.Test != "" {
		s += " · " + e.Test
	}
	return s
}

func dedupKey(n *Node) string {
	secret := n.ID
	if secret == "" {
		secret = n.Username + ":" + n.Password
	}
	if n.Proto == "wireguard" {
		secret = n.PrivateKey + "|" + n.PeerPublicKey
	}
	return fmt.Sprintf("%s|%s|%d|%s|%s", n.Proto, strings.ToLower(n.Address), n.Port, secret, n.Method)
}

var linkRe = regexp.MustCompile(`(vmess|vless|trojan|ss|hysteria2|hysteria|hy2|tuic|wireguard|anytls|ssh|socks5|socks)://[^\s"'<>]+`)
var httpProxyRe = regexp.MustCompile(`https?://[^\s"'<>:/@]+(:[^\s"'<>:/@]*)?@[^\s"'<>]+`)

// ExtractLinks 从任意文本中提取节点链接：支持多行粘贴、链接夹杂在文字中、
// 以及整段 base64（订阅原文直接粘贴）。
func ExtractLinks(text string) []string {
	found := linkRe.FindAllString(text, -1)
	found = append(found, httpProxyRe.FindAllString(text, -1)...)
	if len(found) == 0 {
		compact := strings.Join(strings.Fields(text), "")
		if raw, err := b64Decode(compact); err == nil {
			found = linkRe.FindAllString(string(raw), -1)
			found = append(found, httpProxyRe.FindAllString(string(raw), -1)...)
		}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, f := range found {
		f = strings.TrimRight(f, "，。、；：！？)）]】>\"'")
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func LoadLibrary(root string) []*LibEntry {
	b, err := os.ReadFile(libraryPath(root))
	if err != nil {
		return nil
	}
	entries := []*LibEntry{}
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		n, err := ParseLink(t)
		if err != nil {
			continue
		}
		k := dedupKey(n)
		if seen[k] {
			continue
		}
		seen[k] = true
		entries = append(entries, &LibEntry{Link: t, Node: n})
	}
	return entries
}

func SaveLibrary(root string, entries []*LibEntry) error {
	var sb strings.Builder
	sb.WriteString("# foxkit 节点库（一行一条链接）。这里装的是节点凭证，只存本地/U盘，不要外发。\n")
	for _, e := range entries {
		sb.WriteString(e.Link + "\n")
	}
	return os.WriteFile(libraryPath(root), []byte(sb.String()), 0o644)
}

func ReadCurrentLink(root string) string {
	b, err := os.ReadFile(nodePath(root))
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(ln); t != "" && !strings.HasPrefix(t, "#") {
			return t
		}
	}
	return ""
}

func SaveCurrentLink(root, link string) error {
	return os.WriteFile(nodePath(root), []byte(link+"\n"), 0o644)
}

func LoadSubs(root string) []string {
	b, err := os.ReadFile(subsPath(root))
	if err != nil {
		return nil
	}
	out := []string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(ln); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out
}

func SaveSub(root, subURL string) {
	subs := LoadSubs(root)
	for _, s := range subs {
		if s == subURL {
			return
		}
	}
	subs = append(subs, subURL)
	var sb strings.Builder
	sb.WriteString("# foxkit 订阅地址（一行一个）。订阅地址等同节点凭证，只存本地/U盘，不要外发。\n")
	for _, s := range subs {
		sb.WriteString(s + "\n")
	}
	_ = os.WriteFile(subsPath(root), []byte(sb.String()), 0o644)
}

// FetchSubscription 拉取订阅地址并提取其中的节点链接（base64 或明文清单都处理）。
func FetchSubscription(subURL string) ([]string, error) {
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) foxkit/1.0")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("订阅服务器返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	links := ExtractLinks(string(body))
	if len(links) == 0 {
		return nil, fmt.Errorf("订阅内容里没有找到节点链接（地址可能已失效，或该订阅只对特定客户端返回内容）")
	}
	return links, nil
}

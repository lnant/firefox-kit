package main

// 内置自检：解析 / 分类 / 配置生成 / 导入计数 / 置灰逻辑 / 本地回环连通测试。
// 不依赖外网：连通测试用本机假 SOCKS 服务器 + 本机 HTTP 服务回环完成。

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CheckResult struct {
	Name   string
	OK     bool
	Detail string
}

func check(name string, ok bool, detail string) CheckResult {
	return CheckResult{Name: name, OK: ok, Detail: detail}
}

const (
	sampleVMess = "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3Mtd3MtdGVzdCIsImFkZCI6IjIwMy4wLjExMy4xMCIsInBvcnQiOiI0NDMiLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImNkbi5leGFtcGxlLmNvbSIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ=="
	sampleVLESS = "vless://22222222-3333-4444-5555-666666666666@203.0.113.20:443?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&sni=www.example.com&fp=chrome&type=tcp#vless-reality"
	sampleTrojan = "trojan://passw0rd@203.0.113.30:443?peer=cdn.example.com#trojan-node"
	sampleSS    = "ss://YWVzLTI1Ni1nY206cGFzc3cwcmQ@203.0.113.40:8388#ss-node"
	sampleHY2   = "hysteria2://passw0rd@203.0.113.50:443?insecure=0&sni=hy.example.com&obfs=salamander&obfs-password=obfssecret#hy2-node"
	sampleTUIC  = "tuic://33333333-4444-5555-6666-777777777777:passw0rd@203.0.113.60:443?congestion_control=bbr&sni=tuic.example.com#tuic-node"
	sampleWG    = "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@203.0.113.70:51820?publickey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=&address=172.16.0.2/32&mtu=1280#wg-node"
	sampleAnyTLS = "anytls://passw0rd@203.0.113.80:443?sni=any.example.com#anytls-node"
	sampleSSH   = "ssh://user1:passw0rd@203.0.113.90:22#ssh-node"
	sampleArgo  = "vmess://eyJ2IjoiMiIsInBzIjoiYXJnby1ub2RlIiwiYWRkIjoiYXJnby5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImFyZ28uZXhhbXBsZS5jb20iLCJwYXRoIjoiL2FyZ28iLCJ0bHMiOiJ0bHMifQ=="
)

func RunSelfChecks() []CheckResult {
	var out []CheckResult
	parse := func(name, link, proto string, branch Branch) (*Node, CheckResult) {
		n, err := ParseLink(link)
		if err != nil {
			return nil, check(name, false, "解析失败："+err.Error())
		}
		if n.Proto != proto {
			return nil, check(name, false, "协议不对："+n.Proto)
		}
		if n.Branch() != branch {
			return nil, check(name, false, "分支不对："+n.Branch().Label())
		}
		return n, check(name, true, n.Summary())
	}

	var n *Node
	var c CheckResult

	n, c = parse("解析 vmess", sampleVMess, "vmess", BranchProtocol)
	out = append(out, c)
	if n != nil && (n.Net != "ws" || n.Security != "tls") {
		out = append(out, check("vmess 的 ws+tls 识别", false, n.Net+"/"+n.Security))
	} else if n != nil {
		out = append(out, check("vmess 的 ws+tls 识别", true, "ws + tls"))
	}
	_, c = parse("解析 vless+reality", sampleVLESS, "vless", BranchProtocol)
	out = append(out, c)
	_, c = parse("解析 trojan", sampleTrojan, "trojan", BranchProtocol)
	out = append(out, c)
	ss, c := parse("解析 ss(SIP002)", sampleSS, "ss", BranchProtocol)
	out = append(out, c)
	if ss != nil {
		out = append(out, check("ss 方法/密码", ss.Method == "aes-256-gcm" && ss.ID == "passw0rd", ss.Method))
	}
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw123@203.0.113.41:8389")) + "#legacy"
	_, c = parse("解析 ss(整体编码老格式)", legacy, "ss", BranchProtocol)
	out = append(out, c)
	_, c = parse("解析 hysteria2", sampleHY2, "hysteria2", BranchProtocol)
	out = append(out, c)
	_, c = parse("解析 tuic", sampleTUIC, "tuic", BranchProtocol)
	out = append(out, c)
	wg, c := parse("解析 wireguard", sampleWG, "wireguard", BranchProtocol)
	out = append(out, c)
	_, c = parse("解析 anytls", sampleAnyTLS, "anytls", BranchProtocol)
	out = append(out, c)
	_, c = parse("解析 ssh", sampleSSH, "ssh", BranchProtocol)
	out = append(out, c)
	argo, c := parse("解析 Argo 节点（本质 vmess+ws）", sampleArgo, "vmess", BranchProtocol)
	out = append(out, c)
	if argo != nil {
		out = append(out, check("Argo 按普通 ws 节点处理", argo.Net == "ws" && argo.Address == "argo.example.com", argo.Address))
	}

	_, c = parse("SOCKS 无密码 → 直连分支", "socks5://203.0.113.100:1080#s1", "socks", BranchDirect)
	out = append(out, c)
	_, c = parse("SOCKS 带密码 → 代登录分支", "socks5://user1:passw0rd@203.0.113.101:1080#s2", "socks", BranchAuthRelay)
	out = append(out, c)
	_, c = parse("裸 SOCKS 地址:端口 → 直连", "203.0.113.102:1080", "socks", BranchDirect)
	out = append(out, c)
	_, c = parse("裸 SOCKS 四段带密码 → 代登录", "203.0.113.103:1080:user1:passw0rd", "socks", BranchAuthRelay)
	out = append(out, c)
	_, c = parse("裸 SOCKS 密码@地址 → 代登录", "user1:passw0rd@203.0.113.104:1080", "socks", BranchAuthRelay)
	out = append(out, c)
	_, c = parse("HTTP 代理带账号 → 代登录", "http://user1:passw0rd@203.0.113.105:8080#p1", "http", BranchAuthRelay)
	out = append(out, c)
	if _, err := ParseLink("http://example.com/some/page"); err == nil {
		out = append(out, check("普通网址不当节点", false, "被误收了"))
	} else {
		out = append(out, check("普通网址不当节点", true, err.Error()))
	}

	// 配置生成：逐协议
	for name, link := range map[string]string{
		"vmess": sampleVMess, "vless": sampleVLESS, "trojan": sampleTrojan,
		"ss": sampleSS, "hysteria2": sampleHY2, "tuic": sampleTUIC,
		"anytls": sampleAnyTLS, "ssh": sampleSSH,
		"socks带密码": "socks5://user1:passw0rd@203.0.113.101:1080",
	} {
		nn, err := ParseLink(link)
		if err != nil {
			out = append(out, check("生成配置 "+name, false, err.Error()))
			continue
		}
		cfg, err := BuildConfig(nn, 39901)
		if err != nil {
			out = append(out, check("生成配置 "+name, false, err.Error()))
			continue
		}
		if _, err := json.Marshal(cfg); err != nil {
			out = append(out, check("生成配置 "+name, false, "JSON 失败"))
			continue
		}
		obs := cfg["outbounds"].([]any)
		ob := obs[0].(map[string]any)
		out = append(out, check("生成配置 "+name, ob["tag"] == "proxy", fmt.Sprint(ob["type"])))
	}
	if wg != nil {
		cfg, err := BuildConfig(wg, 39901)
		ok := err == nil && cfg["endpoints"] != nil && cfg["route"].(map[string]any)["final"] == "proxy"
		out = append(out, check("生成配置 wireguard(endpoint)", ok, fmt.Sprint(err)))
	}
	// B 分支的配置必须是「本地无密码入口 + 带账密出口」
	if nn, err := ParseLink("socks5://user1:passw0rd@203.0.113.101:1080"); err == nil {
		cfg, _ := BuildConfig(nn, 39901)
		ob := cfg["outbounds"].([]any)[0].(map[string]any)
		ib := cfg["inbounds"].([]any)[0].(map[string]any)
		ok := ob["username"] == "user1" && ob["password"] == "passw0rd" && ib["type"] == "socks"
		out = append(out, check("代登录分支配置形态", ok, "入口无密码、出口带账密"))
	}
	// XHTTP 明确不支持
	xn, _ := ParseLink("vless://22222222-3333-4444-5555-666666666666@203.0.113.20:443?security=tls&type=xhttp#x")
	if _, err := BuildConfig(xn, 39901); err != nil && strings.Contains(err.Error(), "sing-box") {
		out = append(out, check("XHTTP 明确报不支持", true, err.Error()))
	} else {
		out = append(out, check("XHTTP 明确报不支持", false, fmt.Sprint(err)))
	}
	// 直连分支不生成配置
	if dn, err := ParseLink("socks5://203.0.113.100:1080"); err == nil {
		_, err := BuildConfig(dn, 39901)
		out = append(out, check("直连分支不生成配置", err != nil, ""))
	}

	// 导入计数：2 好 + 1 重复 + 2 坏
	text := strings.Join([]string{
		sampleVMess,
		"这是一段说明文字，里面夹着一条 " + sampleSS + " 链接",
		sampleVMess, // 重复
		"vmess://!!!not-base64!!!",
		"203.0.113.200:99999:user1:passw0rd", // 端口越界
		"203.0.113.201:1080",                  // 裸 SOCKS，好
	}, "\n")
	rep := ImportText(nil, text)
	ok := rep.Added == 3 && rep.Duplicates == 1 && len(rep.Failed) == 2
	out = append(out, check("导入计数反馈", ok,
		fmt.Sprintf("新增 %d / 重复 %d / 失败 %d（期望 3/1/2）", rep.Added, rep.Duplicates, len(rep.Failed))))

	// base64 订阅原文提取
	blob := base64.StdEncoding.EncodeToString([]byte(sampleVMess + "\n" + sampleTrojan))
	links := ExtractLinks(blob)
	out = append(out, check("base64 订阅提取", len(links) == 2, fmt.Sprintf("提取到 %d 条", len(links))))

	// 置灰逻辑
	a0 := ComputeActions(KitState{})
	out = append(out, check("置灰：空库时不能启动且给原因", !a0.CanStart && a0.StartHint != "", a0.StartHint))
	a1 := ComputeActions(KitState{NodeCount: 2, HasCurrent: true, CurrentBranch: BranchProtocol, KernelReady: false, FirefoxReady: true})
	out = append(out, check("置灰：缺内核时不能启动/测试", !a1.CanStart && !a1.CanTestOne && a1.CanPrepareKernel, a1.StartHint))
	a2 := ComputeActions(KitState{NodeCount: 2, HasCurrent: true, CurrentBranch: BranchDirect, FirefoxReady: true})
	out = append(out, check("直连节点不需要内核也能启动", a2.CanStart, a2.StartHint))
	a3 := ComputeActions(KitState{NodeCount: 2, HasCurrent: true, CurrentBranch: BranchProtocol, KernelReady: true, FirefoxReady: true, Running: true})
	out = append(out, check("运行中锁定切换与测试", !a3.CanSelect && !a3.CanTestAll && a3.CanStop && a3.CanImport, a3.SelectHint))

	// 本地回环连通测试（假 SOCKS 服务器 -> 本机 HTTP 204 服务）
	okc, detail := loopbackSocksTest()
	out = append(out, check("回环连通测试（直连分支）", okc, detail))

	// 浏览器企业策略：工具包副本落策略、系统路径不碰
	out = append(out, firefoxPoliciesChecks()...)

	return out
}

// firefoxPoliciesChecks 验证 EnsureFirefoxPolicies：
// 1) 工具目录内的 Firefox 副本会生成含三项策略的 policies.json；
// 2) 已有其他策略时合并保留、且重复调用结果稳定（幂等）；
// 3) 工具目录外的路径（模拟系统安装版）不落任何文件。
func firefoxPoliciesChecks() []CheckResult {
	var out []CheckResult
	root, err := os.MkdirTemp("", "foxkit-pol-root")
	if err != nil {
		return []CheckResult{check("浏览器策略写入", false, err.Error())}
	}
	defer os.RemoveAll(root)
	ffDir := filepath.Join(root, "Surf", "Firefox")
	if err := os.MkdirAll(ffDir, 0o755); err != nil {
		return []CheckResult{check("浏览器策略写入", false, err.Error())}
	}
	ff := filepath.Join(ffDir, firefoxName())
	if err := os.WriteFile(ff, []byte("dummy"), 0o755); err != nil {
		return []CheckResult{check("浏览器策略写入", false, err.Error())}
	}
	target := filepath.Join(ffDir, "distribution", "policies.json")
	readPol := func() map[string]any {
		b, err := os.ReadFile(target)
		if err != nil {
			return nil
		}
		var doc map[string]any
		if json.Unmarshal(b, &doc) != nil {
			return nil
		}
		pol, _ := doc["policies"].(map[string]any)
		return pol
	}
	EnsureFirefoxPolicies(root, ff)
	pol := readPol()
	ok := pol != nil && pol["DisableAppUpdate"] == true &&
		pol["BackgroundAppUpdate"] == false && pol["DisableDefaultBrowserAgent"] == true
	out = append(out, check("浏览器策略写入（关更新/后台任务/默认代理）", ok, fmt.Sprintf("%v", pol)))

	// 合并与幂等：先塞一个无关策略，再调两次，结果应保留无关策略且两次一致
	if pol != nil {
		doc := map[string]any{"policies": map[string]any{"DisablePocket": true}}
		b, _ := json.Marshal(doc)
		_ = os.WriteFile(target, b, 0o644)
		EnsureFirefoxPolicies(root, ff)
		first, _ := os.ReadFile(target)
		EnsureFirefoxPolicies(root, ff)
		second, _ := os.ReadFile(target)
		pol2 := readPol()
		ok2 := pol2 != nil && pol2["DisablePocket"] == true && pol2["DisableAppUpdate"] == true &&
			string(first) == string(second)
		out = append(out, check("浏览器策略合并与幂等", ok2, "保留已有策略、重复写不变化"))
	}

	sysDir, err := os.MkdirTemp("", "foxkit-pol-sys")
	if err == nil {
		defer os.RemoveAll(sysDir)
		sysFF := filepath.Join(sysDir, firefoxName())
		_ = os.WriteFile(sysFF, []byte("dummy"), 0o755)
		EnsureFirefoxPolicies(root, sysFF)
		_, statErr := os.Stat(filepath.Join(sysDir, "distribution"))
		out = append(out, check("系统路径的 Firefox 不落策略", os.IsNotExist(statErr), sysDir))
	}
	return out
}

// loopbackSocksTest 在本机起一个极简 SOCKS5 服务器和一个 204 HTTP 服务，
// 把 www.gstatic.com 替换为本机目标，走 TestNode 的直连路径验证整条链。
// TestNode 的目标写死为 www.gstatic.com:80，这里改用底层 socks5Connect 验证
// 同一条代码路径（TestNode 内部正是用它发请求）。
func loopbackSocksTest() (bool, string) {
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err.Error()
	}
	defer httpLn.Close()
	go func() {
		for {
			c, err := httpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()
	httpPort := httpLn.Addr().(*net.TCPAddr).Port

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, err.Error()
	}
	defer socksLn.Close()
	go serveFakeSocks(socksLn)
	socksPort := socksLn.Addr().(*net.TCPAddr).Port

	conn, err := socks5Connect("127.0.0.1", socksPort, "", "", "127.0.0.1", httpPort, 5*time.Second)
	if err != nil {
		return false, "经假代理连接失败：" + err.Error()
	}
	defer conn.Close()
	// 复用 httpStatusViaConn 的解析逻辑，但目标是本机服务，所以手工发请求
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET http://www.gstatic.com/generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"); err != nil {
		return false, err.Error()
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return false, "读应答失败：" + err.Error()
	}
	if resp.StatusCode != 204 {
		return false, fmt.Sprintf("状态码 %d", resp.StatusCode)
	}
	return true, "假代理转发 -> 本机 204 应答成功"
}

func serveFakeSocks(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 512)
			if _, err := io.ReadFull(c, buf[:2]); err != nil {
				return
			}
			n := int(buf[1])
			if _, err := io.ReadFull(c, buf[:n]); err != nil {
				return
			}
			if _, err := c.Write([]byte{5, 0}); err != nil {
				return
			}
			if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
				return
			}
			var host string
			switch buf[3] {
			case 1:
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				host = net.IP(buf[:4]).String()
			case 3:
				if _, err := io.ReadFull(c, buf[:1]); err != nil {
					return
				}
				l := int(buf[0])
				if _, err := io.ReadFull(c, buf[:l]); err != nil {
					return
				}
				host = string(buf[:l])
			default:
				return
			}
			if _, err := io.ReadFull(c, buf[:2]); err != nil {
				return
			}
			port := int(buf[0])<<8 | int(buf[1])
			up, err := net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), 5*time.Second)
			if err != nil {
				_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer up.Close()
			if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
				return
			}
			go io.Copy(up, c)
			_, _ = io.Copy(c, up)
		}(c)
	}
}

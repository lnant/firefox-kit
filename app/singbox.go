package main

// sing-box 配置生成层。
//
// 统一形态：本地开一个无认证 SOCKS 入口（127.0.0.1:本地端口），出口按节点
// 类型生成。三种分支在这里汇合：
//   A 直连 —— 不生成配置（Firefox 直接连远端），调用方不会走到这里
//   B 代登录 —— 出口就是带账号密码的 socks/http，本地入口不带密码，
//              Firefox 连本地口即可，等于 sing-box 替它登录
//   C 协议节点 —— 出口按 vmess/vless/... 生成；WireGuard 是 endpoint，
//              走 route.final 指向它
//
// sing-box 不支持的传输（如 XHTTP/SplitHTTP）在这里明确报错，不硬凑。

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const LocalPort = 10808

func tlsBlock(n *Node) map[string]any {
	if n.Security != "tls" && n.Security != "reality" {
		// 这些协议默认带 TLS
		switch n.Proto {
		case "trojan", "hysteria", "hysteria2", "tuic", "anytls":
		default:
			if !(n.Proto == "http" && n.Security == "tls") {
				return nil
			}
		}
	}
	t := map[string]any{"enabled": true}
	sn := n.SNI
	if sn == "" {
		sn = n.Host
	}
	if sn == "" {
		sn = n.Address
	}
	if sn != "" {
		t["server_name"] = sn
	}
	if n.Insecure {
		t["insecure"] = true
	}
	if len(n.ALPN) > 0 {
		t["alpn"] = n.ALPN
	}
	if n.Security == "reality" {
		fp := n.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		r := map[string]any{"enabled": true, "public_key": n.PublicKey}
		if n.ShortID != "" {
			r["short_id"] = n.ShortID
		}
		t["reality"] = r
	} else if n.Fingerprint != "" {
		t["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fingerprint}
	}
	return t
}

func transportBlock(n *Node) (map[string]any, error) {
	switch strings.ToLower(n.Net) {
	case "", "tcp", "raw":
		return nil, nil
	case "ws", "websocket":
		p := n.Path
		if p == "" {
			p = "/"
		}
		// sing-box 的 ws 传输类型名就是 "ws"，写 "websocket" 会报 unknown transport type
		tr := map[string]any{"type": "ws", "path": p}
		if n.Host != "" {
			tr["headers"] = map[string]any{"Host": n.Host}
		}
		return tr, nil
	case "grpc":
		svc := n.ServiceName
		if svc == "" {
			svc = n.Path
		}
		return map[string]any{"type": "grpc", "service_name": svc}, nil
	case "http", "h2":
		tr := map[string]any{"type": "http", "path": n.Path}
		if n.Host != "" {
			tr["host"] = []string{n.Host}
		}
		return tr, nil
	case "httpupgrade":
		tr := map[string]any{"type": "httpupgrade", "path": n.Path}
		if n.Host != "" {
			tr["host"] = n.Host
		}
		return tr, nil
	case "quic":
		return map[string]any{"type": "quic"}, nil
	case "xhttp", "splithttp", "split-http":
		return nil, fmt.Errorf("这个节点的传输方式（XHTTP）不在 sing-box 支持范围内，暂时用不了")
	default:
		return nil, fmt.Errorf("这个节点的传输方式（%s）暂时不支持", n.Net)
	}
}

// BuildOutbound 生成节点的出口对象（WireGuard 除外，它是 endpoint）。
func BuildOutbound(n *Node) (map[string]any, error) {
	tr, err := transportBlock(n)
	if err != nil {
		return nil, err
	}
	tls := tlsBlock(n)
	base := map[string]any{"tag": "proxy", "server": n.Address, "server_port": n.Port}
	put := func(k string, v any) {
		if v != nil {
			base[k] = v
		}
	}
	switch n.Proto {
	case "vmess":
		base["type"] = "vmess"
		base["uuid"] = n.ID
		base["security"] = "auto"
		if n.AlterID != 0 {
			base["alter_id"] = n.AlterID
		}
		put("tls", tls)
		put("transport", tr)
	case "vless":
		base["type"] = "vless"
		base["uuid"] = n.ID
		if n.Flow != "" {
			base["flow"] = n.Flow
		}
		if n.PacketEncoding != "" {
			base["packet_encoding"] = n.PacketEncoding
		}
		put("tls", tls)
		put("transport", tr)
	case "trojan":
		base["type"] = "trojan"
		base["password"] = n.ID
		put("tls", tls)
		put("transport", tr)
	case "ss":
		base["type"] = "shadowsocks"
		base["method"] = n.Method
		base["password"] = n.ID
		if n.Plugin != "" {
			// SIP002 的 plugin 形如 "obfs-local;obfs-host=example.com"
			parts := strings.SplitN(n.Plugin, ";", 2)
			base["plugin"] = parts[0]
			if len(parts) == 2 {
				base["plugin_opts"] = parts[1]
			}
		}
		if n.PluginOpts != "" {
			base["plugin_opts"] = n.PluginOpts
		}
	case "hysteria2":
		base["type"] = "hysteria2"
		base["password"] = n.ID
		if n.UpMbps > 0 {
			base["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			base["down_mbps"] = n.DownMbps
		}
		if n.Obfs != "" {
			base["obfs"] = map[string]any{"type": n.Obfs, "password": n.ObfsPassword}
		}
		put("tls", tls)
	case "hysteria":
		base["type"] = "hysteria"
		if n.AuthString != "" {
			base["auth_str"] = n.AuthString
		} else if n.ID != "" {
			base["auth_str"] = n.ID
		}
		// sing-box 的 hysteria v1 出口必须给带宽，链接里没写时用常见默认值
		up := n.UpMbps
		if up <= 0 {
			up = 10
		}
		base["up_mbps"] = up
		down := n.DownMbps
		if down <= 0 {
			down = 50
		}
		base["down_mbps"] = down
		if n.Obfs != "" {
			base["obfs"] = n.ObfsPassword
		}
		put("tls", tls)
	case "tuic":
		base["type"] = "tuic"
		base["uuid"] = n.ID
		base["password"] = n.Password
		if n.Congestion != "" {
			base["congestion_control"] = n.Congestion
		}
		if n.UDPRelay != "" {
			base["udp_relay_mode"] = n.UDPRelay
		}
		// TUIC 的 ALPN 按协议就是 h3：链接没写时补上，
		// 否则对要求 h3 的服务端会报 "tls: no application protocol"。
		if tls != nil {
			if _, ok := tls["alpn"]; !ok {
				tls["alpn"] = []string{"h3"}
			}
		}
		put("tls", tls)
	case "anytls":
		base["type"] = "anytls"
		base["password"] = n.ID
		put("tls", tls)
	case "ssh":
		base["type"] = "ssh"
		base["user"] = n.Username
		if n.Password != "" {
			base["password"] = n.Password
		}
	case "socks":
		base["type"] = "socks"
		base["version"] = "5"
		if n.Username != "" {
			base["username"] = n.Username
		}
		if n.Password != "" {
			base["password"] = n.Password
		}
	case "http":
		base["type"] = "http"
		if n.Username != "" {
			base["username"] = n.Username
		}
		if n.Password != "" {
			base["password"] = n.Password
		}
		put("tls", tls)
	default:
		return nil, fmt.Errorf("协议 %s 暂时不支持", n.Proto)
	}
	return base, nil
}

// BuildEndpoint 生成 WireGuard endpoint。
func BuildEndpoint(n *Node) (map[string]any, error) {
	peer := map[string]any{
		"address":     n.Address,
		"port":        n.Port,
		"public_key":  n.PeerPublicKey,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}
	if n.PreSharedKey != "" {
		peer["pre_shared_key"] = n.PreSharedKey
	}
	if len(n.Reserved) > 0 {
		peer["reserved"] = n.Reserved
	}
	ep := map[string]any{
		"type":       "wireguard",
		"tag":        "proxy",
		"address":    n.LocalAddr,
		"private_key": n.PrivateKey,
		"peers":      []any{peer},
	}
	if n.MTU > 0 {
		ep["mtu"] = n.MTU
	}
	return ep, nil
}

// BuildConfig 生成完整 sing-box 配置。localPort 是本地 SOCKS 入口端口。
func BuildConfig(n *Node, localPort int) (map[string]any, error) {
	if n.Branch() == BranchDirect {
		return nil, fmt.Errorf("这个节点可以直接用，不需要生成配置")
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks-in",
			"listen": "127.0.0.1", "listen_port": localPort,
		}},
		"route": map[string]any{"final": "proxy"},
	}
	if n.Proto == "wireguard" {
		ep, err := BuildEndpoint(n)
		if err != nil {
			return nil, err
		}
		cfg["endpoints"] = []any{ep}
		cfg["outbounds"] = []any{map[string]any{"type": "direct", "tag": "direct"}}
		return cfg, nil
	}
	ob, err := BuildOutbound(n)
	if err != nil {
		return nil, err
	}
	cfg["outbounds"] = []any{ob, map[string]any{"type": "direct", "tag": "direct"}}
	return cfg, nil
}

// WriteConfig 生成并写出配置。先写临时文件，成功后才替换正式文件，并把
// 上一份正式配置留为 .prev 备份——生成失败绝不冲掉上次能用的配置。
func WriteConfig(n *Node, path string, localPort int) error {
	cfg, err := BuildConfig(n, localPort)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = copyFileSimple(path, path+".prev")
	}
	return os.Rename(tmp, path)
}

func copyFileSimple(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

// CheckConfig 用 sing-box 本体自检配置（sing-box check -c）。
// 内核不在时返回 (false, nil)：没法深检，不算失败，调用方按浅校验结果处理。
func CheckConfig(singboxPath, configPath string) (bool, error) {
	if singboxPath == "" || !fileExists(singboxPath) {
		return false, nil
	}
	cmd := exec.Command(singboxPath, "check", "-c", configPath)
	cmd.Dir = filepath.Dir(configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return true, fmt.Errorf("sing-box 自检没通过：%s", firstLine(msg))
	}
	return true, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

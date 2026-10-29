package main

// 功能流程测试：用真实 sing-box 二进制验证
//   1) 每种协议生成的配置能过 sing-box check
//   2) 端到端回环：服务端 sing-box + 本程序生成的客户端配置 + 本地 HTTP 目标
//   3) Runner 启停、配置保留上一份、节点库往返、残留恢复
// sing-box 路径：环境变量 FOXKIT_SINGBOX，默认 ~/workspace/.singbox-test/sing-box。
// 二进制不存在时跳过内核相关项（t.Skip），其余照常。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func singboxBin(t *testing.T) string {
	t.Helper()
	p := os.Getenv("FOXKIT_SINGBOX")
	if p == "" {
		home, _ := os.UserHomeDir()
		p = filepath.Join(home, "workspace", ".singbox-test", "sing-box")
	}
	if !fileExists(p) {
		t.Skipf("sing-box 二进制不存在：%s", p)
	}
	return p
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func runSingbox(t *testing.T, bin, cfgPath string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Dir = filepath.Dir(cfgPath)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("sing-box 启动失败：%v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("sing-box 输出：%s", out.String())
		}
	})
	return cmd
}

// httpTarget 起一个对任何请求都回 204 的本地 HTTP 服务，返回端口。
func httpTarget(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8192)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// fetchViaLocalSocks 走本地 SOCKS 入口取目标，断言拿到 204。
func fetchViaLocalSocks(t *testing.T, socksPort, targetPort int) {
	t.Helper()
	if err := tryFetch(socksPort, targetPort); err != nil {
		t.Fatalf("经客户端 SOCKS 取目标失败：%v", err)
	}
}

func tryFetch(socksPort, targetPort int) error {
	conn, err := socks5Connect("127.0.0.1", socksPort, "", "", "127.0.0.1", targetPort, 8*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	code, err := httpStatusViaConn(conn, 8*time.Second)
	if err != nil {
		return err
	}
	if code != 204 {
		return fmt.Errorf("期望 204，得到 %d", code)
	}
	return nil
}

// loopTest 通用回环：给定服务端配置与客户端节点链接，验证整条链。
// udpServer 为真时服务端只监听 UDP（hy2/tuic），不能用 TCP 探活，改为重试取目标。
func loopTest(t *testing.T, serverCfg map[string]any, serverPort int, clientLink string, udpServer ...bool) {
	t.Helper()
	bin := singboxBin(t)
	dir := t.TempDir()
	targetPort := httpTarget(t)
	udp := len(udpServer) > 0 && udpServer[0]

	srvPath := filepath.Join(dir, "server.json")
	writeJSON(t, srvPath, serverCfg)
	runSingbox(t, bin, srvPath)
	if !udp && !waitPort(serverPort, 6*time.Second) {
		t.Fatalf("服务端 sing-box 端口 %d 未就绪", serverPort)
	}

	node, err := ParseLink(clientLink)
	if err != nil {
		t.Fatalf("客户端节点解析失败：%v", err)
	}
	clientPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := BuildConfig(node, clientPort)
	if err != nil {
		t.Fatalf("客户端配置生成失败：%v", err)
	}
	cliPath := filepath.Join(dir, "client.json")
	writeJSON(t, cliPath, cfg)
	// 先过官方 check 再跑
	if checked, err := CheckConfig(bin, cliPath); !checked || err != nil {
		t.Fatalf("客户端配置 check 未通过：checked=%v err=%v", checked, err)
	}
	runSingbox(t, bin, cliPath)
	if !waitPort(clientPort, 6*time.Second) {
		t.Fatalf("客户端 sing-box 端口未就绪")
	}
	if udp {
		// UDP 服务端无法探活，QUIC 握手也可能要重试几次
		deadline := time.Now().Add(12 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			if err = tryFetch(clientPort, targetPort); err == nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("UDP 回环重试后仍失败：%v", err)
	}
	fetchViaLocalSocks(t, clientPort, targetPort)
}

func directOut() map[string]any {
	return map[string]any{"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
}

func TestSingboxCheckAllConfigs(t *testing.T) {
	bin := singboxBin(t)
	links := map[string]string{
		"vmess": sampleVMess, "vless": sampleVLESS, "trojan": sampleTrojan,
		"ss": sampleSS, "hysteria2": sampleHY2, "tuic": sampleTUIC,
		"wireguard": sampleWG, "anytls": sampleAnyTLS, "ssh": sampleSSH,
		"socks-auth": "socks5://user1:passw0rd@203.0.113.101:1080",
		"http-auth":  "http://user1:passw0rd@203.0.113.105:8080",
		"hysteria":   "hysteria://authstr@203.0.113.51:443?sni=hy.example.com",
	}
	for name, link := range links {
		n, err := ParseLink(link)
		if err != nil {
			t.Errorf("%s 解析失败：%v", name, err)
			continue
		}
		cfgPath := filepath.Join(t.TempDir(), "c.json")
		if err := WriteConfig(n, cfgPath, 39902); err != nil {
			t.Errorf("%s 配置生成失败：%v", name, err)
			continue
		}
		if checked, err := CheckConfig(bin, cfgPath); !checked || err != nil {
			t.Errorf("%s sing-box check 未通过：%v", name, err)
		}
	}
}

func TestLoopShadowsocks(t *testing.T) {
	port, _ := freePort()
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "shadowsocks", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"method": "aes-256-gcm", "password": "passw0rd",
	}}
	link := fmt.Sprintf("ss://YWVzLTI1Ni1nY206cGFzc3cwcmQ@127.0.0.1:%d#loop", port)
	loopTest(t, srv, port, link)
}

func TestLoopVMessTCP(t *testing.T) {
	port, _ := freePort()
	uuid := "11111111-2222-3333-4444-555555555555"
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "vmess", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "u", "uuid": uuid, "alterId": 0}},
	}}
	payload := fmt.Sprintf(`{"v":"2","ps":"loop","add":"127.0.0.1","port":"%d","id":"%s","aid":"0","net":"tcp","type":"none","tls":""}`, port, uuid)
	link := "vmess://" + b64Std(payload)
	loopTest(t, srv, port, link)
}

func TestLoopVLESS(t *testing.T) {
	port, _ := freePort()
	uuid := "22222222-3333-4444-5555-666666666666"
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "u", "uuid": uuid}},
	}}
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#loop", uuid, port)
	loopTest(t, srv, port, link)
}

func TestLoopSocksAuthRelay(t *testing.T) {
	// B 分支：服务端是带账密的 SOCKS，客户端配置负责代登录
	port, _ := freePort()
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"username": "user1", "password": "passw0rd"}},
	}}
	link := fmt.Sprintf("socks5://user1:passw0rd@127.0.0.1:%d#loop", port)
	loopTest(t, srv, port, link)
}

// selfSignedCert 为 127.0.0.1 生成自签证书，返回 (certPath, keyPath)。
func selfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func tlsServerBlock(t *testing.T, dir string) map[string]any {
	cert, key := selfSignedCert(t, dir)
	return map[string]any{"enabled": true, "certificate_path": cert, "key_path": key}
}

func TestLoopTrojan(t *testing.T) {
	port, _ := freePort()
	dir := t.TempDir()
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "trojan", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "u", "password": "passw0rd"}},
		"tls":   tlsServerBlock(t, dir),
	}}
	// 把服务端配置目录与 loopTest 的临时目录对齐：证书已写到 dir，
	// loopTest 用自己的 TempDir 写 server.json，证书路径是绝对路径，没问题。
	link := fmt.Sprintf("trojan://passw0rd@127.0.0.1:%d?allowInsecure=1#loop", port)
	loopTest(t, srv, port, link)
}

func TestLoopAnyTLS(t *testing.T) {
	port, _ := freePort()
	dir := t.TempDir()
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "anytls", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "u", "password": "passw0rd"}},
		"tls":   tlsServerBlock(t, dir),
	}}
	link := fmt.Sprintf("anytls://passw0rd@127.0.0.1:%d?insecure=1#loop", port)
	loopTest(t, srv, port, link)
}

// requireUDP 探测本机 UDP 回环是否可用。本开发沙箱直接禁止 UDP socket
// （连最原始的 UDP 发送都报 operation not permitted），此时 hy2/tuic 的
// 数据面回环在本机做不了，跳过并注明——配置层已由 sing-box check 验证，
// 数据面改到真实服务器上补测（博客机一节）。
func requireUDP(t *testing.T) {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("本机 UDP 不可用（%v），跳过数据面回环", err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port
	// 完整回声往返：本沙箱会静默吞掉 UDP 包（发送不报错但永远收不到回复），
	// 只试发送探不出来，必须等一次真实回复。
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = ln.WriteToUDP(buf[:n], addr)
		}
	}()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Skipf("本机 UDP 不可用（%v），跳过数据面回环", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Skipf("本机 UDP 发送被禁止（%v），跳过数据面回环", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err != nil {
		t.Skipf("本机 UDP 回环收不到回复（%v）——沙箱网络限制，跳过数据面回环", err)
	}
}

func TestLoopHysteria2(t *testing.T) {
	requireUDP(t)
	port, _ := freePort()
	dir := t.TempDir()
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "hysteria2", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "u", "password": "passw0rd"}},
		"tls":   tlsServerBlock(t, dir),
	}}
	link := fmt.Sprintf("hysteria2://passw0rd@127.0.0.1:%d?insecure=1#loop", port)
	loopTest(t, srv, port, link, true)
}

func TestLoopTUIC(t *testing.T) {
	requireUDP(t)
	port, _ := freePort()
	dir := t.TempDir()
	uuid := "33333333-4444-5555-6666-777777777777"
	tlsb := tlsServerBlock(t, dir)
	tlsb["alpn"] = []string{"h3"}
	srv := directOut()
	srv["inbounds"] = []any{map[string]any{
		"type": "tuic", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "u", "uuid": uuid, "password": "passw0rd"}},
		"congestion_control": "bbr",
		"tls":                tlsb,
	}}
	link := fmt.Sprintf("tuic://%s:passw0rd@127.0.0.1:%d?congestion_control=bbr&allow_insecure=1#loop", uuid, port)
	loopTest(t, srv, port, link, true)
}

func TestWriteConfigKeepsPrev(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	n1, _ := ParseLink(sampleVMess)
	n2, _ := ParseLink(sampleTrojan)
	if err := WriteConfig(n1, path, 39903); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if err := WriteConfig(n2, path, 39903); err != nil {
		t.Fatal(err)
	}
	prev, err := os.ReadFile(path + ".prev")
	if err != nil {
		t.Fatalf("没有留下上一份配置：%v", err)
	}
	if string(prev) != string(first) {
		t.Fatalf("上一份配置内容不对")
	}
}

func TestLibraryRoundtrip(t *testing.T) {
	root := t.TempDir()
	rep := ImportText(nil, sampleVMess+"\n"+sampleSS+"\n"+sampleVMess)
	if rep.Added != 2 || rep.Duplicates != 1 {
		t.Fatalf("导入计数不对：%+v", rep)
	}
	if err := SaveLibrary(root, rep.Entries); err != nil {
		t.Fatal(err)
	}
	loaded := LoadLibrary(root)
	if len(loaded) != 2 {
		t.Fatalf("读回 %d 条，期望 2", len(loaded))
	}
	if err := SaveCurrentLink(root, sampleSS); err != nil {
		t.Fatal(err)
	}
	if got := ReadCurrentLink(root); got != sampleSS {
		t.Fatalf("当前节点读回不对")
	}
}

func TestRecoverStale(t *testing.T) {
	root := t.TempDir()
	// 占住本地端口，模拟孤儿内核还在监听
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(LocalPort)))
	if err != nil {
		t.Skipf("本地端口 %d 被占用，跳过：%v", LocalPort, err)
	}
	defer ln.Close()
	sleep := exec.Command("sleep", "60")
	if err := sleep.Start(); err != nil {
		t.Skip("sleep 不可用")
	}
	defer sleep.Process.Kill()
	if err := os.MkdirAll(surfDir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidPath(root), []byte(itoa(sleep.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !RecoverStale(root) {
		t.Fatalf("应报告清理了残留")
	}
	// sleep 应已被杀
	done := make(chan error, 1)
	go func() { done <- sleep.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("残留进程没被清掉")
	}
	if fileExists(pidPath(root)) {
		t.Fatalf("pid 文件应被删除")
	}
}

func b64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

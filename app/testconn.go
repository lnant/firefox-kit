package main

// 连通测试（与导入的格式校验完全分开）：选中节点之后单独做的事，
// 结果只写回节点的 Test 字段，不改当前节点、不改正式配置。
//
// 测法按分支：
//   A 直连   —— 直接走远端 SOCKS / HTTP 代理发一个请求，不需要内核
//   B/C      —— 用 sing-box 在临时端口起这条节点，再走本地口发请求；
//               临时实例与正式运行用不同端口，互不抢占；内核没备好时
//               明确返回「需要先准备内核」，不当作节点不通

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const testTargetURL = "http://www.gstatic.com/generate_204"

type TestResult struct {
	OK      bool
	Latency int // 毫秒；失败为 0
	Msg     string
}

func (r TestResult) Display() string {
	if r.OK {
		return fmt.Sprintf("可用 · %dms", r.Latency)
	}
	return "不可用 · " + r.Msg
}

// socks5Connect 通过 SOCKS5 代理（可带账密）连到目标地址，返回裸连接。
func socks5Connect(proxyHost string, proxyPort int, user, pass, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(proxyHost, itoa(proxyPort)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	fail := func(e error) (net.Conn, error) {
		conn.Close()
		return nil, e
	}
	// 握手：提供 无认证 / 账密 两种方法
	methods := []byte{0}
	if user != "" {
		methods = append(methods, 2)
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return fail(err)
	}
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fail(err)
	}
	if buf[0] != 5 {
		return fail(fmt.Errorf("代理应答异常"))
	}
	switch buf[1] {
	case 0:
	case 2:
		if len(user) > 255 || len(pass) > 255 {
			return fail(fmt.Errorf("账号或密码太长"))
		}
		var b []byte
		b = append(b, 1, byte(len(user)))
		b = append(b, user...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		if _, err := conn.Write(b); err != nil {
			return fail(err)
		}
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return fail(err)
		}
		if buf[1] != 0 {
			return fail(fmt.Errorf("代理账号密码不对"))
		}
	case 0xFF:
		return fail(fmt.Errorf("代理不接受任何认证方式"))
	default:
		return fail(fmt.Errorf("代理要求不支持的认证方式"))
	}
	// CONNECT 请求
	var req []byte
	ip := net.ParseIP(targetHost)
	switch {
	case ip != nil && ip.To4() != nil:
		req = []byte{5, 1, 0, 1}
		req = append(req, ip.To4()...)
	case ip != nil:
		req = []byte{5, 1, 0, 4}
		req = append(req, ip.To16()...)
	default:
		if len(targetHost) > 255 {
			return fail(fmt.Errorf("目标地址太长"))
		}
		req = []byte{5, 1, 0, 3, byte(len(targetHost))}
		req = append(req, targetHost...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(targetPort))
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return fail(err)
	}
	if buf[1] != 0 {
		return fail(fmt.Errorf("代理连接目标失败（代码 %d）", buf[1]))
	}
	switch buf[3] {
	case 1:
		_, err = io.ReadFull(conn, buf[:4+2])
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err == nil {
			_, err = io.ReadFull(conn, buf[:int(buf[0])+2])
		}
	case 4:
		_, err = io.ReadFull(conn, buf[:16+2])
	}
	if err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// httpStatusViaConn 在已建好的连接上发一个 HTTP 请求，返回状态码。
func httpStatusViaConn(conn net.Conn, timeout time.Duration) (int, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := "GET " + testTargetURL + " HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\nUser-Agent: foxkit/1.0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var proto string
	var code int
	if _, err := fmt.Sscanf(line, "%s %d", &proto, &code); err != nil {
		return 0, fmt.Errorf("应答看不懂：%s", strings.TrimSpace(line))
	}
	return code, nil
}

// httpProxyFetchVia 通过无/有认证的 HTTP 代理以绝对 URI 形式发请求（直连分支的 HTTP 代理测法）。
func testHTTPProxyDirect(n *Node, timeout time.Duration) TestResult {
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(n.Address, itoa(n.Port)))
	if err != nil {
		return TestResult{Msg: "连不上代理：" + shortErr(err)}
	}
	defer conn.Close()
	code, err := httpStatusViaConn(conn, timeout)
	if err != nil {
		return TestResult{Msg: "代理没有正常应答：" + shortErr(err)}
	}
	if code == 204 || (code >= 200 && code < 400) {
		return TestResult{OK: true, Latency: int(time.Since(start).Milliseconds())}
	}
	if code == 407 {
		return TestResult{Msg: "代理需要账号密码"}
	}
	return TestResult{Msg: fmt.Sprintf("应答状态 %d", code)}
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "超时"
	}
	s := err.Error()
	s = strings.TrimPrefix(s, "dial tcp ")
	return firstLine(s)
}

// TestNode 测一个节点的连通性。kernelPath 为 sing-box 路径（B/C 类需要）。
func TestNode(root string, e *LibEntry, kernelPath string) TestResult {
	n := e.Node
	const timeout = 10 * time.Second
	switch n.Branch() {
	case BranchDirect:
		if n.Proto == "http" {
			return testHTTPProxyDirect(n, timeout)
		}
		start := time.Now()
		conn, err := socks5Connect(n.Address, n.Port, "", "", "www.gstatic.com", 80, timeout)
		if err != nil {
			return TestResult{Msg: shortErr(err)}
		}
		defer conn.Close()
		code, err := httpStatusViaConn(conn, timeout)
		if err != nil {
			return TestResult{Msg: "连上代理但请求失败：" + shortErr(err)}
		}
		if code == 204 || (code >= 200 && code < 400) {
			return TestResult{OK: true, Latency: int(time.Since(start).Milliseconds())}
		}
		return TestResult{Msg: fmt.Sprintf("应答状态 %d", code)}

	default: // B / C：临时起 sing-box
		if kernelPath == "" || !fileExists(kernelPath) {
			return TestResult{Msg: "需要先准备内核"}
		}
		port, err := freePort()
		if err != nil {
			return TestResult{Msg: "本地端口分配失败"}
		}
		tmpDir := filepath.Join(root, "Surf", "tmp")
		_ = os.MkdirAll(tmpDir, 0o755)
		cfgPath := filepath.Join(tmpDir, fmt.Sprintf("test-%d.json", port))
		if err := WriteConfig(n, cfgPath, port); err != nil {
			return TestResult{Msg: err.Error()}
		}
		defer os.Remove(cfgPath)
		cmd := exec.Command(kernelPath, "run", "-c", cfgPath)
		cmd.Dir = tmpDir
		prepCmd(cmd)
		var out strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Start(); err != nil {
			return TestResult{Msg: "内核启动失败：" + shortErr(err)}
		}
		defer func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
		}()
		if !waitPort(port, 5*time.Second) {
			msg := strings.TrimSpace(out.String())
			if msg != "" {
				return TestResult{Msg: "内核没起来：" + firstLine(msg)}
			}
			return TestResult{Msg: "内核没起来（端口未就绪）"}
		}
		start := time.Now()
		conn, err := socks5Connect("127.0.0.1", port, "", "", "www.gstatic.com", 80, timeout)
		if err != nil {
			return TestResult{Msg: shortErr(err)}
		}
		defer conn.Close()
		code, err := httpStatusViaConn(conn, timeout)
		if err != nil {
			return TestResult{Msg: "请求失败：" + shortErr(err)}
		}
		if code == 204 || (code >= 200 && code < 400) {
			return TestResult{OK: true, Latency: int(time.Since(start).Milliseconds())}
		}
		return TestResult{Msg: fmt.Sprintf("应答状态 %d", code)}
	}
}

// TestAll 顺序测全部节点（逐个起临时实例，避免抢端口），支持取消与进度回调。
func TestAll(ctx context.Context, root string, entries []*LibEntry, kernelPath string,
	progress func(done, total int, e *LibEntry, r TestResult)) {
	for i, e := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}
		r := TestNode(root, e, kernelPath)
		e.Test = r.Display()
		if progress != nil {
			progress(i+1, len(entries), e, r)
		}
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 300*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(120 * time.Millisecond)
	}
	return false
}

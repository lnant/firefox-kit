package main

// 节点模型与链接解析（sing-box 内核）。
//
// 支持的输入都以 sing-box 能实现的协议为准：
//   vmess / vless / trojan / shadowsocks(ss) / hysteria / hysteria2(hy2) /
//   tuic / wireguard / anytls / ssh / socks(socks5) / http 代理
// SOCKS 有两种裸写格式也认：地址:端口:用户名:密码、地址:端口@用户名:密码。
//
// Argo 节点本质是 vmess/vless + WebSocket 经 Cloudflare 隧道，链接形态与
// 普通 ws 节点一致，这里按普通节点解析，不设特殊分支。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Branch 是节点在运行时的处理分支（内部概念，不要求用户理解）：
//   A —— 可直连：无认证的 SOCKS / HTTP 代理，Firefox 直接连，不需要内核
//   B —— 需代登录：带用户名密码的 SOCKS / HTTP 代理，Firefox 不支持填
//        SOCKS 密码，必须由 sing-box 在本地代登录后转发
//   C —— 协议节点：vmess/vless 等，必须由 sing-box 转换
type Branch int

const (
	BranchDirect Branch = iota
	BranchAuthRelay
	BranchProtocol
)

func (b Branch) Label() string {
	switch b {
	case BranchDirect:
		return "直连"
	case BranchAuthRelay:
		return "代登录"
	default:
		return "协议转换"
	}
}

type Node struct {
	Proto    string // vmess/vless/trojan/ss/hysteria/hysteria2/tuic/wireguard/anytls/ssh/socks/http
	Name     string
	Address  string
	Port     int
	ID       string // uuid（vmess/vless/tuic）或密码（trojan/ss/anytls/hysteria2）
	AlterID  int
	Net      string // tcp / ws / grpc / http / httpupgrade / quic
	Security string // tls / reality / none

	Host        string
	Path        string
	SNI         string
	Flow        string
	PublicKey   string
	ShortID     string
	SpiderX     string
	Fingerprint string
	ServiceName    string
	PacketEncoding string // vless 的 packetEncoding 参数
	Insecure       bool
	ALPN           []string

	// ss
	Method     string
	Plugin     string
	PluginOpts string

	// socks / http 代理与 ssh 的账号密码
	Username string
	Password string

	// hysteria / hysteria2
	Obfs         string
	ObfsPassword string
	UpMbps       int
	DownMbps     int
	AuthString   string // hysteria v1 的 auth_str

	// tuic
	Congestion string
	UDPRelay   string

	// wireguard
	PrivateKey    string
	PeerPublicKey string
	PreSharedKey  string
	LocalAddr     []string
	Reserved      []int
	MTU           int
}

func (n *Node) Branch() Branch {
	switch n.Proto {
	case "socks", "http":
		if n.Username == "" && n.Password == "" {
			return BranchDirect
		}
		return BranchAuthRelay
	default:
		return BranchProtocol
	}
}

// TypeLabel 给用户看的简短类型标签（只报协议名，不解释分支）。
func (n *Node) TypeLabel() string {
	switch n.Proto {
	case "ss":
		return "Shadowsocks"
	case "socks":
		return "SOCKS"
	case "http":
		return "HTTP代理"
	case "hysteria2":
		return "Hysteria2"
	case "hysteria":
		return "Hysteria"
	case "wireguard":
		return "WireGuard"
	default:
		return strings.ToUpper(n.Proto[:1]) + n.Proto[1:]
	}
}

func (n *Node) Summary() string {
	return fmt.Sprintf("%s · %s:%d", n.TypeLabel(), n.Address, n.Port)
}

func (n *Node) DisplayName() string {
	if n.Name != "" {
		return n.Name
	}
	return fmt.Sprintf("%s:%d", n.Address, n.Port)
}

func b64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("base64 解码失败")
}

// SupportedSchemes 是导入提取时认的链接前缀。
var SupportedSchemes = []string{
	"vmess://", "vless://", "trojan://", "ss://", "hysteria://", "hysteria2://",
	"hy2://", "tuic://", "wireguard://", "anytls://", "ssh://",
	"socks://", "socks5://",
}

// ParseLink 解析一条节点链接；http(s):// 只在带账号信息时认作 HTTP 代理节点
// （无账号的 http 链接多半是普通网址或订阅地址，不当节点处理）。
func ParseLink(link string) (*Node, error) {
	link = strings.TrimSpace(link)
	lower := strings.ToLower(link)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMess(link[len("vmess://"):])
	case strings.HasPrefix(lower, "vless://"):
		return parseProtoURL(link, "vless")
	case strings.HasPrefix(lower, "trojan://"):
		return parseProtoURL(link, "trojan")
	case strings.HasPrefix(lower, "ss://"):
		return parseSS(link)
	case strings.HasPrefix(lower, "hysteria2://"):
		return parseHysteria2(link, "hysteria2")
	case strings.HasPrefix(lower, "hy2://"):
		return parseHysteria2(link, "hysteria2")
	case strings.HasPrefix(lower, "hysteria://"):
		return parseHysteria2(link, "hysteria")
	case strings.HasPrefix(lower, "tuic://"):
		return parseTUIC(link)
	case strings.HasPrefix(lower, "wireguard://"):
		return parseWireGuard(link)
	case strings.HasPrefix(lower, "anytls://"):
		return parseProtoURL(link, "anytls")
	case strings.HasPrefix(lower, "ssh://"):
		return parseSSH(link)
	case strings.HasPrefix(lower, "socks://"):
		return parseSocksURL(link, "socks")
	case strings.HasPrefix(lower, "socks5://"):
		return parseSocksURL(link, "socks5")
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return parseHTTPProxy(link)
	}
	// 裸 SOCKS 写法：地址:端口:用户名:密码 / 地址:端口@用户名:密码 / 地址:端口
	if n, err := parseBareSocks(link); err == nil {
		return n, nil
	}
	return nil, fmt.Errorf("看不出这是什么节点（只支持 sing-box 的协议链接）")
}

func parseVMess(body string) (*Node, error) {
	if i := strings.IndexAny(body, "#?"); i >= 0 {
		body = body[:i]
	}
	raw, err := b64Decode(body)
	if err != nil {
		return nil, fmt.Errorf("vmess 内容解码失败")
	}
	var j map[string]any
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("vmess 内容不是有效的节点数据")
	}
	get := func(k string) string {
		if v, ok := j[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				return t
			case float64:
				return strconv.Itoa(int(t))
			}
		}
		return ""
	}
	n := &Node{Proto: "vmess"}
	n.Name = get("ps")
	n.Address = get("add")
	n.Port, _ = strconv.Atoi(get("port"))
	n.ID = get("id")
	n.AlterID, _ = strconv.Atoi(get("aid"))
	n.Net = get("net")
	if n.Net == "" {
		n.Net = "tcp"
	}
	n.Host, n.Path, n.SNI = get("host"), get("path"), get("sni")
	if get("tls") == "tls" {
		n.Security = "tls"
	} else {
		n.Security = "none"
	}
	if v := get("alpn"); v != "" {
		n.ALPN = splitComma(v)
	}
	if n.Address == "" || n.ID == "" || !validPort(n.Port) {
		return nil, fmt.Errorf("vmess 内容缺少地址、端口或 UUID")
	}
	return n, nil
}

// parseProtoURL 解析 vless / trojan / anytls 这类标准 URL 形态。
func parseProtoURL(link, proto string) (*Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败")
	}
	n := &Node{Proto: proto}
	name, _ := url.QueryUnescape(u.Fragment)
	n.Name = name
	switch proto {
	case "vless":
		if u.User != nil {
			n.ID = u.User.Username()
		}
	case "trojan", "anytls":
		if u.User != nil {
			pw, _ := u.User.Password()
			if pw != "" {
				n.ID = pw
				n.Username = u.User.Username()
			} else {
				n.ID = u.User.Username()
			}
		}
		n.Security = "tls"
	}
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		n.Port = 443
	}
	q := u.Query()
	n.Net = q.Get("type")
	if n.Net == "" {
		n.Net = "tcp"
	}
	if proto == "vless" {
		n.Security = q.Get("security")
		if n.Security == "" {
			n.Security = "none"
		}
		n.Flow = q.Get("flow")
		n.PublicKey = q.Get("pbk")
		n.ShortID = q.Get("sid")
		n.SpiderX = q.Get("spx")
		n.Fingerprint = q.Get("fp")
		n.PacketEncodingQ(q)
	}
	n.Host = q.Get("host")
	n.Path = q.Get("path")
	n.SNI = q.Get("sni")
	if n.SNI == "" {
		n.SNI = q.Get("peer")
	}
	n.ServiceName = q.Get("serviceName")
	n.Insecure = q.Get("allowInsecure") == "1" || q.Get("insecure") == "1"
	if v := q.Get("alpn"); v != "" {
		n.ALPN = splitComma(v)
	}
	if n.Address == "" || n.ID == "" {
		return nil, fmt.Errorf("链接缺少服务器地址或密钥")
	}
	if !validPort(n.Port) {
		return nil, fmt.Errorf("端口不对：%d", n.Port)
	}
	return n, nil
}

// PacketEncodingQ 读取 vless 的 packetEncoding 参数。
func (n *Node) PacketEncodingQ(q url.Values) {
	n.PacketEncoding = q.Get("packetEncoding")
}

func parseSS(link string) (*Node, error) {
	rest := link[len("ss://"):]
	n := &Node{Proto: "ss", Net: "tcp", Security: "none"}
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ := url.QueryUnescape(rest[i+1:])
		n.Name = name
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		q, _ := url.ParseQuery(rest[i+1:])
		n.Plugin = q.Get("plugin")
		if n.Plugin == "" {
			// SIP002: plugin 值本身包含参数，如 obfs-local;obfs-host=x
			n.Plugin = q.Get("plugin-opts")
		}
		rest = rest[:i]
	}
	if strings.Contains(rest, "@") {
		// ss://base64(method:password)@host:port 或 ss://method:password@host:port
		at := strings.LastIndex(rest, "@")
		userinfo, hostport := rest[:at], rest[at+1:]
		if dec, err := b64Decode(userinfo); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("ss 链接缺少加密方法或密码")
		}
		n.Method, n.ID = parts[0], parts[1]
		host, port, err := splitHostPort(hostport)
		if err != nil {
			return nil, err
		}
		n.Address, n.Port = host, port
	} else {
		// ss://base64(method:password@host:port) 整体编码的老格式
		dec, err := b64Decode(rest)
		if err != nil {
			return nil, fmt.Errorf("ss 内容解码失败")
		}
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, fmt.Errorf("ss 内容格式不对")
		}
		parts := strings.SplitN(s[:at], ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("ss 链接缺少加密方法或密码")
		}
		n.Method, n.ID = parts[0], parts[1]
		host, port, err := splitHostPort(s[at+1:])
		if err != nil {
			return nil, err
		}
		n.Address, n.Port = host, port
	}
	if n.Method == "" || n.ID == "" || n.Address == "" || !validPort(n.Port) {
		return nil, fmt.Errorf("ss 链接缺少方法、密码、地址或端口")
	}
	return n, nil
}

func parseHysteria2(link, proto string) (*Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败")
	}
	n := &Node{Proto: proto, Net: "tcp", Security: "tls"}
	name, _ := url.QueryUnescape(u.Fragment)
	n.Name = name
	if u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			n.Username = u.User.Username()
			n.ID = pw
		} else {
			n.ID = u.User.Username()
		}
	}
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		n.Port = 443
	}
	q := u.Query()
	n.SNI = q.Get("sni")
	n.Insecure = q.Get("insecure") == "1" || q.Get("allowInsecure") == "1"
	n.Obfs = q.Get("obfs")
	n.ObfsPassword = q.Get("obfs-password")
	if n.ObfsPassword == "" {
		n.ObfsPassword = q.Get("obfsParam")
	}
	n.UpMbps, _ = strconv.Atoi(q.Get("upmbps"))
	n.DownMbps, _ = strconv.Atoi(q.Get("downmbps"))
	n.AuthString = q.Get("auth")
	if v := q.Get("alpn"); v != "" {
		n.ALPN = splitComma(v)
	}
	if n.Address == "" || !validPort(n.Port) {
		return nil, fmt.Errorf("链接缺少服务器地址或端口")
	}
	if proto == "hysteria2" && n.ID == "" {
		return nil, fmt.Errorf("hysteria2 链接缺少密码")
	}
	return n, nil
}

func parseTUIC(link string) (*Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败")
	}
	n := &Node{Proto: "tuic", Net: "tcp", Security: "tls"}
	name, _ := url.QueryUnescape(u.Fragment)
	n.Name = name
	if u.User != nil {
		n.ID = u.User.Username() // uuid
		n.Password, _ = u.User.Password()
	}
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		n.Port = 443
	}
	q := u.Query()
	n.SNI = q.Get("sni")
	n.Congestion = q.Get("congestion_control")
	if n.Congestion == "" {
		n.Congestion = q.Get("congestionControl")
	}
	n.UDPRelay = q.Get("udp_relay_mode")
	n.Insecure = q.Get("allow_insecure") == "1" || q.Get("insecure") == "1" || q.Get("allowInsecure") == "1"
	if v := q.Get("alpn"); v != "" {
		n.ALPN = splitComma(v)
	}
	if n.Address == "" || n.ID == "" || !validPort(n.Port) {
		return nil, fmt.Errorf("tuic 链接缺少地址、端口或 UUID")
	}
	return n, nil
}

func parseWireGuard(link string) (*Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败")
	}
	n := &Node{Proto: "wireguard", Net: "udp", Security: "none"}
	name, _ := url.QueryUnescape(u.Fragment)
	n.Name = name
	if u.User != nil {
		key, _ := url.QueryUnescape(u.User.Username())
		n.PrivateKey = key
	}
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		n.Port = 51820
	}
	q := u.Query()
	n.PeerPublicKey = q.Get("publickey")
	if n.PeerPublicKey == "" {
		n.PeerPublicKey = q.Get("publicKey")
	}
	if n.PeerPublicKey == "" {
		n.PeerPublicKey = q.Get("pk")
	}
	n.PreSharedKey = q.Get("presharedkey")
	if a := q.Get("address"); a != "" {
		n.LocalAddr = splitComma(a)
	} else if a := q.Get("ip"); a != "" {
		n.LocalAddr = splitComma(a)
	}
	if r := q.Get("reserved"); r != "" {
		for _, p := range splitComma(r) {
			if v, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				n.Reserved = append(n.Reserved, v)
			}
		}
	}
	n.MTU, _ = strconv.Atoi(q.Get("mtu"))
	if n.PrivateKey == "" || n.PeerPublicKey == "" || n.Address == "" {
		return nil, fmt.Errorf("wireguard 链接缺少私钥、公钥或地址")
	}
	if len(n.LocalAddr) == 0 {
		n.LocalAddr = []string{"172.16.0.2/32"}
	}
	return n, nil
}

func parseSSH(link string) (*Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败")
	}
	n := &Node{Proto: "ssh", Net: "tcp", Security: "none"}
	name, _ := url.QueryUnescape(u.Fragment)
	n.Name = name
	if u.User != nil {
		n.Username = u.User.Username()
		n.Password, _ = u.User.Password()
	}
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		n.Port = 22
	}
	if n.Address == "" || n.Username == "" {
		return nil, fmt.Errorf("ssh 链接缺少地址或用户名")
	}
	return n, nil
}

func parseSocksURL(link, scheme string) (*Node, error) {
	// 变体：socks5://base64(user:pass)@host:port（部分机场的写法）
	if rest := link[len(scheme)+3:]; !strings.Contains(rest, "@") || strings.Count(rest, "@") == 1 {
		// 常规走 url.Parse；base64 变体在常规解析失败或缺少地址时再兜底
		if u, err := url.Parse(link); err == nil && u.Hostname() != "" {
			n := &Node{Proto: "socks", Net: "tcp", Security: "none"}
			name, _ := url.QueryUnescape(u.Fragment)
			n.Name = name
			n.Address = u.Hostname()
			n.Port, _ = strconv.Atoi(u.Port())
			if u.User != nil {
				n.Username = u.User.Username()
				n.Password, _ = u.User.Password()
				// base64 变体：username 本身是 base64(user:pass)
				if n.Password == "" && n.Username != "" {
					if dec, err := b64Decode(n.Username); err == nil && strings.Contains(string(dec), ":") {
						parts := strings.SplitN(string(dec), ":", 2)
						n.Username, n.Password = parts[0], parts[1]
					}
				}
			}
			if n.Port == 0 {
				n.Port = 1080
			}
			if !validPort(n.Port) {
				return nil, fmt.Errorf("端口不对：%d", n.Port)
			}
			return n, nil
		}
	}
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("socks 链接解析失败")
	}
	n := &Node{Proto: "socks", Net: "tcp", Security: "none"}
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		n.Port = 1080
	}
	if u.User != nil {
		n.Username = u.User.Username()
		n.Password, _ = u.User.Password()
	}
	return n, nil
}

func parseHTTPProxy(link string) (*Node, error) {
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("链接解析失败")
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("这是普通网址，不是代理节点（HTTP 代理节点需要带账号）")
	}
	n := &Node{Proto: "http", Net: "tcp"}
	name, _ := url.QueryUnescape(u.Fragment)
	n.Name = name
	n.Address = u.Hostname()
	n.Port, _ = strconv.Atoi(u.Port())
	if n.Port == 0 {
		if strings.HasPrefix(strings.ToLower(link), "https://") {
			n.Port = 443
		} else {
			n.Port = 80
		}
	}
	if strings.HasPrefix(strings.ToLower(link), "https://") {
		n.Security = "tls"
	}
	n.Username = u.User.Username()
	n.Password, _ = u.User.Password()
	if !validPort(n.Port) {
		return nil, fmt.Errorf("端口不对：%d", n.Port)
	}
	return n, nil
}

// parseBareSocks 解析无 scheme 的 SOCKS 写法：
//   地址:端口            （无密码）
//   地址:端口:用户名:密码
//   地址:端口@用户名:密码
//   用户名:密码@地址:端口
func parseBareSocks(s string) (*Node, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t/") {
		return nil, fmt.Errorf("不是裸 SOCKS 写法")
	}
	n := &Node{Proto: "socks", Net: "tcp", Security: "none", Port: 1080}
	// 用户名:密码@地址:端口
	if strings.Contains(s, "@") {
		at := strings.LastIndex(s, "@")
		left, right := s[:at], s[at+1:]
		// 两种方向都试：哪边能拆出合法主机:端口，哪边就是地址
		if host, port, err := splitHostPort(right); err == nil {
			n.Address, n.Port = host, port
			if strings.Contains(left, ":") {
				p := strings.SplitN(left, ":", 2)
				n.Username, n.Password = p[0], p[1]
			}
			return n, nil
		}
		if host, port, err := splitHostPort(left); err == nil {
			n.Address, n.Port = host, port
			if strings.Contains(right, ":") {
				p := strings.SplitN(right, ":", 2)
				n.Username, n.Password = p[0], p[1]
			}
			return n, nil
		}
		return nil, fmt.Errorf("裸 SOCKS 写法里找不到合法的地址:端口")
	}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 2:
		port, err := strconv.Atoi(parts[1])
		if err != nil || !validPort(port) || parts[0] == "" {
			return nil, fmt.Errorf("不是裸 SOCKS 写法")
		}
		n.Address, n.Port = parts[0], port
		return n, nil
	case 4:
		port, err := strconv.Atoi(parts[1])
		if err != nil || !validPort(port) || parts[0] == "" {
			return nil, fmt.Errorf("不是裸 SOCKS 写法")
		}
		// IPv6 裸写会落到这里但 parts[0] 为空/带括号，不认，避免误判
		n.Address, n.Port = parts[0], port
		n.Username, n.Password = parts[2], parts[3]
		return n, nil
	}
	return nil, fmt.Errorf("不是裸 SOCKS 写法")
}

func splitHostPort(hp string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		// 容忍没写端口的情形由调用方处理；这里要求带端口
		return "", 0, fmt.Errorf("地址格式不对：%s", hp)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !validPort(port) {
		return "", 0, fmt.Errorf("端口不对：%s", portStr)
	}
	if host == "" {
		return "", 0, fmt.Errorf("地址为空")
	}
	return host, port, nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func splitComma(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

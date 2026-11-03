package main

// 手工输入模板（仿 NekoBox 的手动输入）：点「手工输入」先按协议选一张
// 配置表，再在表里填关键信息、选传输与安全类型，程序拼成标准节点链接
// 入库。协议范围 = sing-box 7 合 1 用到的 + SOCKS：
//   VLESS / VMess / Hysteria2 / TUIC / AnyTLS / SOCKS5
// 7 合 1 的七种链都落在这些表里：Reality 与 WS+TLS 是 VLESS 表里
// 「传输层安全 / 传输协议」两个选项的组合，Argo 与直连是 VMess 表里
// TLS 开关的区别。拼出的链接必须能被 ParseLink 原样解析（自检逐项验）。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// FieldSpec 模板里的一个输入项；Choices 非空表示下拉选择。
type FieldSpec struct {
	Key      string
	Label    string
	Default  string
	Required bool
	Choices  []string
}

// ManualTemplate 一种协议的手工输入模板（一张配置表）。
type ManualTemplate struct {
	ID     string
	Title  string
	Fields []FieldSpec
	Build  func(v map[string]string) (string, error)
}

func fName() FieldSpec { return FieldSpec{Key: "name", Label: "配置名称（可空）"} }
func fAddr() FieldSpec {
	return FieldSpec{Key: "address", Label: "服务器", Required: true}
}
func fPort(def string) FieldSpec {
	return FieldSpec{Key: "port", Label: "服务器端口", Default: def, Required: true}
}
func fUUID() FieldSpec { return FieldSpec{Key: "uuid", Label: "用户 ID（UUID）", Required: true} }
func fPassword() FieldSpec {
	return FieldSpec{Key: "password", Label: "密码", Required: true}
}
func fInsecure() FieldSpec {
	return FieldSpec{Key: "insecure", Label: "跳过证书验证", Default: "否", Choices: []string{"否", "是"}}
}

// ManualTemplates 全部模板，顺序即选择列表里的顺序。
var ManualTemplates = []ManualTemplate{
	{
		ID: "vless", Title: "VLESS",
		Fields: []FieldSpec{
			fName(), fAddr(), fPort("443"), fUUID(),
			{Key: "encryption", Label: "加密", Default: "none"},
			{Key: "packetEncoding", Label: "包编码", Default: "（无）", Choices: []string{"（无）", "xudp", "packet"}},
			{Key: "type", Label: "传输协议", Default: "tcp", Choices: []string{"tcp", "ws", "grpc", "httpupgrade"}},
			{Key: "security", Label: "传输层安全", Default: "none", Choices: []string{"none", "tls", "reality"}},
			{Key: "flow", Label: "流控 flow", Default: "（无）", Choices: []string{"（无）", "xtls-rprx-vision"}},
			{Key: "path", Label: "路径 path（ws 用）"},
			{Key: "host", Label: "Host（ws 用，可空 = 同服务器）"},
			{Key: "serviceName", Label: "服务名 serviceName（grpc 用）"},
			{Key: "sni", Label: "SNI（tls / reality 用）"},
			{Key: "pbk", Label: "公钥 publicKey（reality 用）"},
			{Key: "sid", Label: "短ID shortId（reality 用，可空）"},
			{Key: "fp", Label: "指纹 fingerprint", Default: "chrome", Choices: []string{"chrome", "firefox", "safari", "ios", "android", "edge", "random"}},
		},
		Build: func(v map[string]string) (string, error) {
			q := url.Values{}
			q.Set("encryption", v["encryption"])
			q.Set("security", v["security"])
			q.Set("type", v["type"])
			if v["packetEncoding"] != "（无）" {
				q.Set("packetEncoding", v["packetEncoding"])
			}
			if v["flow"] != "（无）" {
				q.Set("flow", v["flow"])
			}
			switch v["type"] {
			case "ws", "httpupgrade":
				path := v["path"]
				if path == "" {
					path = "/"
				}
				q.Set("path", path)
				host := v["host"]
				if host == "" {
					host = v["address"]
				}
				q.Set("host", host)
			case "grpc":
				if v["serviceName"] != "" {
					q.Set("serviceName", v["serviceName"])
				}
			}
			if v["security"] == "tls" || v["security"] == "reality" {
				sni := v["sni"]
				if sni == "" {
					sni = v["address"]
				}
				q.Set("sni", sni)
			}
			if v["security"] == "reality" {
				if v["pbk"] == "" {
					return "", fmt.Errorf("请填写「公钥 publicKey（reality 用）」")
				}
				q.Set("pbk", v["pbk"])
				if v["sid"] != "" {
					q.Set("sid", v["sid"])
				}
				q.Set("fp", v["fp"])
			}
			return buildURL("vless", url.User(v["uuid"]), v, q), nil
		},
	},
	{
		ID: "vmess", Title: "VMess",
		Fields: []FieldSpec{
			fName(), fAddr(), fPort("443"), fUUID(),
			{Key: "alterId", Label: "替代 ID", Default: "0"},
			{Key: "encryption", Label: "加密", Default: "auto", Choices: []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}},
			{Key: "type", Label: "传输协议", Default: "ws", Choices: []string{"ws", "tcp", "grpc", "http"}},
			{Key: "tls", Label: "传输层加密 TLS", Default: "开", Choices: []string{"开", "关"}},
			{Key: "host", Label: "Host（可空，空 = 同服务器）"},
			{Key: "path", Label: "路径 path", Default: "/"},
			{Key: "sni", Label: "SNI（可空）"},
		},
		Build: func(v map[string]string) (string, error) {
			host := v["host"]
			if host == "" && (v["type"] == "ws" || v["type"] == "http") {
				host = v["address"]
			}
			tls := ""
			if v["tls"] == "开" {
				tls = "tls"
			}
			j := struct {
				V    string `json:"v"`
				Ps   string `json:"ps"`
				Add  string `json:"add"`
				Port string `json:"port"`
				ID   string `json:"id"`
				Aid  string `json:"aid"`
				Scy  string `json:"scy"`
				Net  string `json:"net"`
				Type string `json:"type"`
				Host string `json:"host"`
				Path string `json:"path"`
				TLS  string `json:"tls"`
				SNI  string `json:"sni"`
			}{"2", v["name"], v["address"], v["port"], v["uuid"], v["alterId"], v["encryption"], v["type"], "none", host, v["path"], tls, v["sni"]}
			raw, err := json.Marshal(j)
			if err != nil {
				return "", err
			}
			return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
		},
	},
	{
		ID: "hysteria2", Title: "Hysteria2",
		Fields: []FieldSpec{
			fName(), fAddr(), fPort("443"), fPassword(),
			{Key: "sni", Label: "SNI（可空）"}, fInsecure(),
			{Key: "obfs", Label: "混淆类型（可空，如 salamander）"},
			{Key: "obfspw", Label: "混淆密码（可空）"},
		},
		Build: func(v map[string]string) (string, error) {
			q := url.Values{}
			if v["sni"] != "" {
				q.Set("sni", v["sni"])
			}
			q.Set("insecure", yesNo(v["insecure"]))
			if v["obfs"] != "" {
				q.Set("obfs", v["obfs"])
				if v["obfspw"] != "" {
					q.Set("obfs-password", v["obfspw"])
				}
			}
			return buildURL("hysteria2", url.User(v["password"]), v, q), nil
		},
	},
	{
		ID: "tuic", Title: "TUIC",
		Fields: []FieldSpec{
			fName(), fAddr(), fPort("443"), fUUID(), fPassword(),
			{Key: "sni", Label: "SNI（可空）"},
			{Key: "congestion", Label: "拥塞控制", Default: "bbr", Choices: []string{"bbr", "cubic", "new_reno"}},
			fInsecure(),
		},
		Build: func(v map[string]string) (string, error) {
			q := url.Values{}
			q.Set("congestion_control", v["congestion"])
			if v["sni"] != "" {
				q.Set("sni", v["sni"])
			}
			q.Set("allow_insecure", yesNo(v["insecure"]))
			return buildURL("tuic", url.UserPassword(v["uuid"], v["password"]), v, q), nil
		},
	},
	{
		ID: "anytls", Title: "AnyTLS",
		Fields: []FieldSpec{
			fName(), fAddr(), fPort("443"), fPassword(),
			{Key: "sni", Label: "SNI（可空）"}, fInsecure(),
		},
		Build: func(v map[string]string) (string, error) {
			q := url.Values{}
			if v["sni"] != "" {
				q.Set("sni", v["sni"])
			}
			q.Set("insecure", yesNo(v["insecure"]))
			return buildURL("anytls", url.User(v["password"]), v, q), nil
		},
	},
	{
		ID: "socks5", Title: "SOCKS",
		Fields: []FieldSpec{
			fName(), fAddr(), fPort("1080"),
			{Key: "username", Label: "用户名（可空）"},
			{Key: "password", Label: "密码（可空）"},
		},
		Build: func(v map[string]string) (string, error) {
			var user *url.Userinfo
			if v["username"] != "" {
				if v["password"] != "" {
					user = url.UserPassword(v["username"], v["password"])
				} else {
					user = url.User(v["username"])
				}
			}
			return buildURL("socks5", user, v, nil), nil
		},
	},
}

// BuildManualLink 按模板校验必填与端口，再拼链接。
// 返回的链接保证能被 ParseLink 接受（拼完自检一遍，不合格算内部错误）。
func BuildManualLink(t *ManualTemplate, vals map[string]string) (string, error) {
	v := map[string]string{}
	for _, f := range t.Fields {
		val := strings.TrimSpace(vals[f.Key])
		if val == "" {
			val = f.Default
		}
		if f.Required && val == "" {
			return "", fmt.Errorf("请填写「%s」", f.Label)
		}
		v[f.Key] = val
	}
	if p, err := strconv.Atoi(v["port"]); err != nil || !validPort(p) {
		return "", fmt.Errorf("端口不对：%s", v["port"])
	}
	link, err := t.Build(v)
	if err != nil {
		return "", err
	}
	if _, err := ParseLink(link); err != nil {
		return "", fmt.Errorf("拼出的链接自检没通过：%v", err)
	}
	return link, nil
}

// buildURL 组装 scheme://user@地址:端口?参数#名称 形态的链接。
func buildURL(scheme string, user *url.Userinfo, v map[string]string, q url.Values) string {
	port, _ := strconv.Atoi(v["port"])
	u := url.URL{
		Scheme:   scheme,
		User:     user,
		Host:     net.JoinHostPort(v["address"], strconv.Itoa(port)),
		Fragment: v["name"],
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func yesNo(s string) string {
	if s == "是" {
		return "1"
	}
	return "0"
}

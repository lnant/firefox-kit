# foxkit 脚本版：把 node.txt 里的节点生成 sing-box 配置与浏览器配置。
#
# 用法：
#   powershell -NoProfile -File mkconfig.ps1 -Probe        只探活（给 Start.bat 检测执行策略用）
#   powershell -NoProfile -File mkconfig.ps1 -List         校验 node.txt 里全部节点，打印计数与清单
#   powershell -NoProfile -File mkconfig.ps1 -Pick 2       用第 2 条有效节点生成配置
#
# 退出码：0 = 已生成内核配置（B/C 类）；10 = 直连节点（A 类，不需要内核）；
#         2 = 没有可用节点；3 = 生成失败；4 = 需要内核但 Surf\core 里没有 sing-box
# 脚本只做本地文件读写：不下载、不联网、不改系统设置。
param(
  [switch]$Probe,
  [switch]$List,
  [int]$Pick = 0,
  [string]$Root = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
if ($Probe) { exit 0 }

$LocalPort = 10808
$NodeFile = Join-Path $Root 'node.txt'
$Surf = Join-Path $Root 'Surf'
$CfgFile = Join-Path $Surf 'config.json'
$ProfileDir = Join-Path $Surf 'ff-data'
$CountFile = Join-Path $Surf 'valid-count.txt'

function B64Text($s) {
  $s = $s.Trim().Replace('-', '+').Replace('_', '/')
  while (($s.Length % 4) -ne 0) { $s += '=' }
  return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
}
function QParse($q) {
  $h = @{}
  if ($q) {
    foreach ($pair in $q.Split('&')) {
      if ($pair -eq '') { continue }
      $kv = $pair.Split('=', 2)
      $k = [Uri]::UnescapeDataString($kv[0].Replace('+', ' '))
      $v = ''
      if ($kv.Count -gt 1) { $v = [Uri]::UnescapeDataString($kv[1].Replace('+', ' ')) }
      $h[$k] = $v
    }
  }
  return $h
}
function ValidPort($p) { return ($p -ge 1 -and $p -le 65535) }

# 把一行拆成 协议/用户信息/地址/端口/路径/查询/备注
function SplitLink($link) {
  if ($link -notmatch '^([a-zA-Z0-9]+)://(.+)$') { return $null }
  $scheme = $Matches[1].ToLower()
  $rest = $Matches[2]
  $frag = ''
  $i = $rest.IndexOf('#')
  if ($i -ge 0) { $frag = [Uri]::UnescapeDataString($rest.Substring($i + 1)); $rest = $rest.Substring(0, $i) }
  $query = ''
  $i = $rest.IndexOf('?')
  if ($i -ge 0) { $query = $rest.Substring($i + 1); $rest = $rest.Substring(0, $i) }
  $path = ''
  $i = $rest.IndexOf('/')
  $authority = $rest
  if ($i -ge 0) { $authority = $rest.Substring(0, $i); $path = $rest.Substring($i) }
  $user = ''
  $i = $authority.LastIndexOf('@')
  if ($i -ge 0) { $user = $authority.Substring(0, $i); $authority = $authority.Substring($i + 1) }
  $hn = $authority; $port = 0
  if ($authority -match '^\[(.+)\]:(\d+)$') { $hn = $Matches[1]; $port = [int]$Matches[2] }
  elseif ($authority -match '^(.+):(\d+)$') { $hn = $Matches[1]; $port = [int]$Matches[2] }
  return @{ Scheme = $scheme; User = $user; Host = $hn; Port = $port; Path = $path; Query = (QParse $query); Name = $frag; RawQuery = $query }
}

function NewNode($proto) {
  return @{ Proto = $proto; Name = ''; Address = ''; Port = 0; ID = ''; AlterID = 0; Net = 'tcp'; Security = 'none';
            Host = ''; Path = ''; SNI = ''; Flow = ''; PublicKey = ''; ShortID = ''; Fingerprint = ''; ServiceName = '';
            Insecure = $false; Method = ''; Username = ''; Password = ''; Obfs = ''; ObfsPassword = ''; AuthString = ''; Congestion = ''; ALPN = '' }
}
function NodeOK($n) {
  if (-not $n.Address) { throw '缺少服务器地址' }
  if (-not (ValidPort $n.Port)) { throw ('端口不对：' + $n.Port) }
}

function ParseLink($link) {
  $link = $link.Trim()
  $lower = $link.ToLower()
  # ---- vmess ----
  if ($lower.StartsWith('vmess://')) {
    $body = $link.Substring(8)
    $cut = $body.IndexOfAny([char[]]'#?')
    if ($cut -ge 0) { $body = $body.Substring(0, $cut) }
    try { $j = B64Text $body | ConvertFrom-Json } catch { throw 'vmess 内容解码失败' }
    $n = NewNode 'vmess'
    $n.Name = [string]$j.ps; $n.Address = [string]$j.add; $n.Port = [int]$j.port; $n.ID = [string]$j.id
    if ($j.aid) { $n.AlterID = [int]$j.aid }
    if ($j.net) { $n.Net = [string]$j.net }
    $n.Host = [string]$j.host; $n.Path = [string]$j.path; $n.SNI = [string]$j.sni
    if ($j.tls -eq 'tls') { $n.Security = 'tls' }
    if (-not $n.ID) { throw 'vmess 内容缺少 UUID' }
    NodeOK $n; return $n
  }
  # ---- 裸 SOCKS（无协议头）----
  if ($link -notmatch '://') {
    return ParseBareSocks $link
  }
  $p = SplitLink $link
  if (-not $p) { throw '看不出这是什么节点' }
  switch ($p.Scheme) {
    'vless' {
      $n = NewNode 'vless'
      $n.Name = $p.Name; $n.Address = $p.Host; $n.Port = $p.Port; if ($n.Port -eq 0) { $n.Port = 443 }
      $n.ID = [Uri]::UnescapeDataString($p.User)
      $q = $p.Query
      if ($q['type']) { $n.Net = $q['type'] }
      if ($q['security']) { $n.Security = $q['security'] }
      $n.Flow = $q['flow']; $n.PublicKey = $q['pbk']; $n.ShortID = $q['sid']; $n.Fingerprint = $q['fp']
      $n.Host = $q['host']; $n.Path = $q['path']; $n.SNI = $q['sni']; if (-not $n.SNI) { $n.SNI = $q['peer'] }
      $n.ServiceName = $q['serviceName']
      if ($q['allowInsecure'] -eq '1' -or $q['insecure'] -eq '1') { $n.Insecure = $true }
      if (-not $n.ID) { throw '链接缺少密钥' }
      NodeOK $n; return $n
    }
    'trojan' {
      $n = NewNode 'trojan'; $n.Security = 'tls'
      $n.Name = $p.Name; $n.Address = $p.Host; $n.Port = $p.Port; if ($n.Port -eq 0) { $n.Port = 443 }
      $ui = [Uri]::UnescapeDataString($p.User)
      $n.ID = $ui
      $q = $p.Query
      if ($q['type']) { $n.Net = $q['type'] }
      $n.Host = $q['host']; $n.Path = $q['path']; $n.SNI = $q['sni']; if (-not $n.SNI) { $n.SNI = $q['peer'] }
      $n.ServiceName = $q['serviceName']
      if ($q['allowInsecure'] -eq '1' -or $q['insecure'] -eq '1') { $n.Insecure = $true }
      if (-not $n.ID) { throw '链接缺少密码' }
      NodeOK $n; return $n
    }
    'anytls' { throw '脚本版暂不支持 anytls，请用程序版' }
    'wireguard' { throw '脚本版暂不支持 WireGuard，请用程序版' }
    'ssh' { throw '脚本版暂不支持 SSH 节点，请用程序版' }
    'ss' { return ParseSS $link $p }
    'hysteria2' { return ParseHy2 $link $p 'hysteria2' }
    'hy2' { return ParseHy2 $link $p 'hysteria2' }
    'hysteria' { throw '脚本版暂不支持 Hysteria v1，请用程序版' }
    'tuic' {
      $n = NewNode 'tuic'; $n.Security = 'tls'
      $n.Name = $p.Name; $n.Address = $p.Host; $n.Port = $p.Port; if ($n.Port -eq 0) { $n.Port = 443 }
      $ui = [Uri]::UnescapeDataString($p.User)
      $parts = $ui.Split(':', 2)
      $n.ID = $parts[0]; if ($parts.Count -gt 1) { $n.Password = $parts[1] }
      $q = $p.Query
      $n.SNI = $q['sni']; $n.Congestion = $q['congestion_control']; $n.ALPN = $q['alpn']
      if ($q['allow_insecure'] -eq '1' -or $q['insecure'] -eq '1' -or $q['allowInsecure'] -eq '1') { $n.Insecure = $true }
      if (-not $n.ID) { throw 'tuic 链接缺少 UUID' }
      NodeOK $n; return $n
    }
    { $_ -in 'socks', 'socks5' } {
      $n = NewNode 'socks'
      $n.Name = $p.Name; $n.Address = $p.Host; $n.Port = $p.Port; if ($n.Port -eq 0) { $n.Port = 1080 }
      if ($p.User) {
        $ui = [Uri]::UnescapeDataString($p.User)
        $parts = $ui.Split(':', 2)
        if ($parts.Count -eq 2) { $n.Username = $parts[0]; $n.Password = $parts[1] }
        else {
          # base64(用户名:密码) 变体
          try { $dec = B64Text $ui; $dp = $dec.Split(':', 2); if ($dp.Count -eq 2) { $n.Username = $dp[0]; $n.Password = $dp[1] } else { $n.Username = $ui } }
          catch { $n.Username = $ui }
        }
      }
      NodeOK $n; return $n
    }
    { $_ -in 'http', 'https' } {
      if (-not $p.User) { throw '这是普通网址，不是代理节点（HTTP 代理节点需要带账号）' }
      $n = NewNode 'http'
      $n.Name = $p.Name; $n.Address = $p.Host
      $n.Port = $p.Port; if ($n.Port -eq 0) { $n.Port = $(if ($p.Scheme -eq 'https') { 443 } else { 80 }) }
      if ($p.Scheme -eq 'https') { $n.Security = 'tls' }
      $ui = [Uri]::UnescapeDataString($p.User)
      $parts = $ui.Split(':', 2)
      $n.Username = $parts[0]; if ($parts.Count -gt 1) { $n.Password = $parts[1] }
      NodeOK $n; return $n
    }
    default { throw ('看不出这是什么节点（协议：' + $p.Scheme + '）') }
  }
}

function ParseSS($link, $p) {
  $n = NewNode 'ss'
  $n.Name = $p.Name
  $rest = $link.Substring(5)
  $cut = $rest.IndexOf('#'); if ($cut -ge 0) { $rest = $rest.Substring(0, $cut) }
  $cut = $rest.IndexOf('?'); if ($cut -ge 0) { $rest = $rest.Substring(0, $cut) }
  $at = $rest.LastIndexOf('@')
  if ($at -ge 0) {
    $ui = $rest.Substring(0, $at); $hp = $rest.Substring($at + 1)
    try { $dec = B64Text $ui; if ($dec.Contains(':')) { $ui = $dec } } catch { $ui = [Uri]::UnescapeDataString($ui) }
    $parts = $ui.Split(':', 2)
    if ($parts.Count -ne 2) { throw 'ss 链接缺少加密方法或密码' }
    $n.Method = $parts[0]; $n.ID = $parts[1]
    $hpParts = $hp.Split(':')
    $n.Address = $hpParts[0]; $n.Port = [int]$hpParts[$hpParts.Count - 1]
  } else {
    try { $dec = B64Text $rest } catch { throw 'ss 内容解码失败' }
    $at2 = $dec.LastIndexOf('@'); if ($at2 -lt 0) { throw 'ss 内容格式不对' }
    $parts = $dec.Substring(0, $at2).Split(':', 2)
    if ($parts.Count -ne 2) { throw 'ss 链接缺少加密方法或密码' }
    $n.Method = $parts[0]; $n.ID = $parts[1]
    $hpParts = $dec.Substring($at2 + 1).Split(':')
    $n.Address = $hpParts[0]; $n.Port = [int]$hpParts[$hpParts.Count - 1]
  }
  if (-not $n.Method -or -not $n.ID) { throw 'ss 链接缺少加密方法或密码' }
  NodeOK $n; return $n
}

function ParseHy2($link, $p, $proto) {
  $n = NewNode $proto; $n.Security = 'tls'
  $n.Name = $p.Name; $n.Address = $p.Host; $n.Port = $p.Port; if ($n.Port -eq 0) { $n.Port = 443 }
  $ui = [Uri]::UnescapeDataString($p.User)
  $parts = $ui.Split(':', 2)
  if ($parts.Count -eq 2 -and $p.User.Contains(':')) { $n.Username = $parts[0]; $n.ID = $parts[1] } else { $n.ID = $ui }
  $q = $p.Query
  $n.SNI = $q['sni']
  if ($q['insecure'] -eq '1' -or $q['allowInsecure'] -eq '1') { $n.Insecure = $true }
  $n.Obfs = $q['obfs']; $n.ObfsPassword = $q['obfs-password']; $n.ALPN = $q['alpn']
  if (-not $n.ID) { throw 'hysteria2 链接缺少密码' }
  NodeOK $n; return $n
}

function ParseBareSocks($s) {
  $s = $s.Trim()
  if ($s -match '\s' -or $s -notmatch ':') { throw '看不出这是什么节点' }
  $n = NewNode 'socks'; $n.Port = 1080
  if ($s.Contains('@')) {
    $at = $s.LastIndexOf('@')
    $left = $s.Substring(0, $at); $right = $s.Substring($at + 1)
    foreach ($try in @(@($right, $left), @($left, $right))) {
      if ($try[0] -match '^(.+):(\d+)$' -and (ValidPort ([int]$Matches[2]))) {
        $n.Address = $Matches[1]; $n.Port = [int]$Matches[2]
        $cred = $try[1].Split(':', 2)
        if ($cred.Count -eq 2) { $n.Username = $cred[0]; $n.Password = $cred[1] }
        NodeOK $n; return $n
      }
    }
    throw '裸 SOCKS 写法里找不到合法的地址:端口'
  }
  $parts = $s.Split(':')
  if ($parts.Count -eq 2 -and (ValidPort ([int]$parts[1]))) {
    $n.Address = $parts[0]; $n.Port = [int]$parts[1]; NodeOK $n; return $n
  }
  if ($parts.Count -eq 4 -and (ValidPort ([int]$parts[1]))) {
    $n.Address = $parts[0]; $n.Port = [int]$parts[1]; $n.Username = $parts[2]; $n.Password = $parts[3]; NodeOK $n; return $n
  }
  throw '看不出这是什么节点'
}

function GetBranch($n) {
  if ($n.Proto -eq 'socks' -or $n.Proto -eq 'http') {
    if (-not $n.Username -and -not $n.Password) { return 'A' }
    return 'B'
  }
  return 'C'
}
function DisplayName($n) {
  if ($n.Name) { return $n.Name }
  return ($n.Address + ':' + $n.Port)
}

function TlsBlock($n) {
  $need = $false
  if ($n.Security -eq 'tls' -or $n.Security -eq 'reality') { $need = $true }
  if ($n.Proto -in 'trojan', 'hysteria2', 'tuic') { $need = $true }
  if ($n.Proto -eq 'http' -and $n.Security -eq 'tls') { $need = $true }
  if (-not $need) { return $null }
  $t = [ordered]@{ enabled = $true }
  $sn = $n.SNI; if (-not $sn) { $sn = $n.Host }; if (-not $sn) { $sn = $n.Address }
  if ($sn) { $t['server_name'] = $sn }
  if ($n.Insecure) { $t['insecure'] = $true }
  $alpn = $n.ALPN
  if (-not $alpn -and $n.Proto -eq 'tuic') { $alpn = 'h3' }
  if ($alpn) { $t['alpn'] = @($alpn.Split(',') | ForEach-Object { $_.Trim() }) }
  if ($n.Security -eq 'reality') {
    $fp = $n.Fingerprint; if (-not $fp) { $fp = 'chrome' }
    $t['utls'] = [ordered]@{ enabled = $true; fingerprint = $fp }
    $r = [ordered]@{ enabled = $true; public_key = $n.PublicKey }
    if ($n.ShortID) { $r['short_id'] = $n.ShortID }
    $t['reality'] = $r
  } elseif ($n.Fingerprint) {
    $t['utls'] = [ordered]@{ enabled = $true; fingerprint = $n.Fingerprint }
  }
  return $t
}
function TransportBlock($n) {
  switch ($n.Net.ToLower()) {
    { $_ -in '', 'tcp', 'raw' } { return $null }
    { $_ -in 'ws', 'websocket' } {
      $path = $n.Path; if (-not $path) { $path = '/' }
      $tr = [ordered]@{ type = 'ws'; path = $path }
      if ($n.Host) { $tr['headers'] = [ordered]@{ Host = $n.Host } }
      return $tr
    }
    'grpc' {
      $svc = $n.ServiceName; if (-not $svc) { $svc = $n.Path }
      return [ordered]@{ type = 'grpc'; service_name = $svc }
    }
    { $_ -in 'http', 'h2' } {
      $tr = [ordered]@{ type = 'http'; path = $n.Path }
      if ($n.Host) { $tr['host'] = @($n.Host) }
      return $tr
    }
    'httpupgrade' {
      $tr = [ordered]@{ type = 'httpupgrade'; path = $n.Path }
      if ($n.Host) { $tr['host'] = $n.Host }
      return $tr
    }
    { $_ -in 'xhttp', 'splithttp' } { throw '这个节点的传输方式（XHTTP）不在 sing-box 支持范围内，暂时用不了' }
    default { throw ('这个节点的传输方式（' + $n.Net + '）暂时不支持') }
  }
}

function BuildConfig($n) {
  $tls = TlsBlock $n
  $tr = TransportBlock $n
  $ob = [ordered]@{ tag = 'proxy'; server = $n.Address; server_port = $n.Port }
  switch ($n.Proto) {
    'vmess' {
      $ob['type'] = 'vmess'; $ob['uuid'] = $n.ID; $ob['security'] = 'auto'
      if ($n.AlterID -ne 0) { $ob['alter_id'] = $n.AlterID }
    }
    'vless' {
      $ob['type'] = 'vless'; $ob['uuid'] = $n.ID
      if ($n.Flow) { $ob['flow'] = $n.Flow }
    }
    'trojan' { $ob['type'] = 'trojan'; $ob['password'] = $n.ID }
    'ss' { $ob['type'] = 'shadowsocks'; $ob['method'] = $n.Method; $ob['password'] = $n.ID }
    'hysteria2' {
      $ob['type'] = 'hysteria2'; $ob['password'] = $n.ID
      if ($n.Obfs) { $ob['obfs'] = [ordered]@{ type = $n.Obfs; password = $n.ObfsPassword } }
    }
    'tuic' {
      $ob['type'] = 'tuic'; $ob['uuid'] = $n.ID; $ob['password'] = $n.Password
      if ($n.Congestion) { $ob['congestion_control'] = $n.Congestion }
    }
    'socks' {
      $ob['type'] = 'socks'; $ob['version'] = '5'
      if ($n.Username) { $ob['username'] = $n.Username }
      if ($n.Password) { $ob['password'] = $n.Password }
    }
    'http' {
      $ob['type'] = 'http'
      if ($n.Username) { $ob['username'] = $n.Username }
      if ($n.Password) { $ob['password'] = $n.Password }
    }
    default { throw ('脚本版暂不支持协议：' + $n.Proto) }
  }
  if ($tls) { $ob['tls'] = $tls }
  if ($tr) { $ob['transport'] = $tr }
  $cfg = [ordered]@{
    log = [ordered]@{ level = 'warn'; timestamp = $true }
    inbounds = @([ordered]@{ type = 'socks'; tag = 'socks-in'; listen = '127.0.0.1'; listen_port = $LocalPort })
    outbounds = @($ob, [ordered]@{ type = 'direct'; tag = 'direct' })
    route = [ordered]@{ final = 'proxy' }
  }
  return $cfg
}

function WriteUserJS($n) {
  if (-not (Test-Path -LiteralPath $ProfileDir)) { New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null }
  $lines = @('// foxkit 脚本版自动生成：代理指向与隐私设置。')
  $branch = GetBranch $n
  $lines += 'user_pref("network.proxy.type", 1);'
  if ($branch -eq 'A' -and $n.Proto -eq 'http') {
    $lines += ('user_pref("network.proxy.http", "' + $n.Address + '");')
    $lines += ('user_pref("network.proxy.http_port", ' + $n.Port + ');')
    $lines += ('user_pref("network.proxy.ssl", "' + $n.Address + '");')
    $lines += ('user_pref("network.proxy.ssl_port", ' + $n.Port + ');')
  } elseif ($branch -eq 'A') {
    $lines += ('user_pref("network.proxy.socks", "' + $n.Address + '");')
    $lines += ('user_pref("network.proxy.socks_port", ' + $n.Port + ');')
    $lines += 'user_pref("network.proxy.socks_version", 5);'
    $lines += 'user_pref("network.proxy.socks_remote_dns", true);'
  } else {
    $lines += 'user_pref("network.proxy.socks", "127.0.0.1");'
    $lines += ('user_pref("network.proxy.socks_port", ' + $LocalPort + ');')
    $lines += 'user_pref("network.proxy.socks_version", 5);'
    $lines += 'user_pref("network.proxy.socks_remote_dns", true);'
  }
  $lines += 'user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");'
  $lines += 'user_pref("media.peerconnection.enabled", false);'
  $lines += 'user_pref("network.trr.mode", 5);'
  $lines += 'user_pref("toolkit.telemetry.enabled", false);'
  $lines += 'user_pref("browser.shell.checkDefaultBrowser", false);'
  $lines += 'user_pref("browser.aboutwelcome.enabled", false);'
  [IO.File]::WriteAllText((Join-Path $ProfileDir 'user.js'), ($lines -join "`n"), (New-Object Text.UTF8Encoding($false)))
}

# ---------------- 主流程 ----------------
if (-not (Test-Path -LiteralPath $NodeFile)) {
  Write-Host '没有找到 node.txt，请把节点粘贴到工具目录的 node.txt 里。'
  exit 2
}
$valid = @()
$failed = @()
foreach ($ln in (Get-Content -LiteralPath $NodeFile)) {
  $t = $ln.Trim()
  if ($t -eq '' -or $t.StartsWith('#')) { continue }
  # 一行里夹着链接时只取链接部分
  $m = [regex]::Match($t, '(vmess|vless|trojan|ss|hysteria2|hysteria|hy2|tuic|wireguard|anytls|ssh|socks5|socks)://[^\s"'']+')
  if ($m.Success) { $t = $m.Value }
  try {
    $n = ParseLink $t
    $valid += @{ Node = $n; Link = $t }
  } catch {
    $short = $t; if ($short.Length -gt 50) { $short = $short.Substring(0, 50) + '…' }
    $failed += ($short + ' —— ' + $_.Exception.Message)
  }
}
if ($List) {
  Write-Host ('可用节点 ' + $valid.Count + ' 条，格式不对 ' + $failed.Count + ' 条（已跳过）：')
  $i = 0
  foreach ($v in $valid) {
    $i++
    Write-Host ('  ' + $i + '. ' + (DisplayName $v.Node) + ' · ' + $v.Node.Proto + ' · ' + $v.Node.Address + ':' + $v.Node.Port)
  }
  foreach ($f in $failed) { Write-Host ('  ✘ ' + $f) }
  if (-not (Test-Path -LiteralPath $Surf)) { New-Item -ItemType Directory -Path $Surf -Force | Out-Null }
  [IO.File]::WriteAllText($CountFile, [string]$valid.Count)
  if ($valid.Count -eq 0) { exit 2 }
  exit 0
}
if ($Pick -lt 1) { $Pick = 1 }
if ($valid.Count -eq 0) {
  Write-Host 'node.txt 里没有可用的节点。格式不对的有：'
  foreach ($f in $failed) { Write-Host ('  ✘ ' + $f) }
  exit 2
}
if ($Pick -gt $valid.Count) { $Pick = 1 }
$chosen = $valid[$Pick - 1].Node
$branch = GetBranch $chosen
Write-Host ('选中节点：' + (DisplayName $chosen) + '（' + $chosen.Proto + '）')
try {
  if ($branch -eq 'A') {
    WriteUserJS $chosen
    Write-Host '这是直连节点，不需要内核，浏览器配置已写好。'
    exit 10
  }
  $kernel = Join-Path (Join-Path $Surf 'core') 'sing-box.exe'
  if (-not (Test-Path -LiteralPath $kernel)) {
    Write-Host '这个节点需要 sing-box 内核，但 Surf\core 里没有 sing-box.exe。'
    Write-Host '请先用程序版准备内核，或手动把官方 sing-box.exe 放到 Surf\core 文件夹里。'
    exit 4
  }
  $cfg = BuildConfig $chosen
  if (-not (Test-Path -LiteralPath $Surf)) { New-Item -ItemType Directory -Path $Surf -Force | Out-Null }
  $json = $cfg | ConvertTo-Json -Depth 20
  $tmp = $CfgFile + '.tmp'
  [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
  # 内核自检：过不了就保留上一份配置
  $checkOut = & $kernel check -c $tmp 2>&1
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    Write-Host ('sing-box 自检没通过，已保留上一份配置：' + ($checkOut | Select-Object -First 1))
    exit 3
  }
  if (Test-Path -LiteralPath $CfgFile) { Copy-Item -LiteralPath $CfgFile -Destination ($CfgFile + '.prev') -Force }
  Move-Item -LiteralPath $tmp -Destination $CfgFile -Force
  WriteUserJS $chosen
  Write-Host '配置已生成并通过自检。'
  exit 0
} catch {
  Write-Host ('生成失败：' + $_.Exception.Message)
  exit 3
}

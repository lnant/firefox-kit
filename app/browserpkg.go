package main

// 浏览器来源之二：从 Firefox 官方完整版安装包直接提取程序文件。
//
// 官方完整版安装包（Firefox Setup *.exe，约 90MB）本质是一个自解压
// 7z 包：里面 core/ 目录就是完整的 Firefox 程序文件。用纯 Go 的 7z
// 读取库把 core/ 提取到 Surf/Firefox，全程不运行安装程序、不写注册表、
// 不装服务——等于“利用安装包复制”，原电脑上不用先装 Firefox。
// 已在开发机上对官方 159.0 安装包实测：提取结果与 7-Zip 官方工具
// 解出的 core/ 逐字节一致。
//
// 在线安装包（stub，只有几百 KB）里没有 core/，提取时会明确报错。

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bodgit/sevenzip"
)

// FindFirefoxInstaller 在工具根目录找 Firefox 安装包文件。
// 认官方命名（Firefox Setup 159.0.exe）与常见改名（Firefox_Setup_159.0.exe）。
// 多个候选时返回最大的那个（完整版远大于在线版）。
func FindFirefoxInstaller(root string) string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var cands []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".exe") {
			continue
		}
		if !strings.Contains(lower, "firefox") {
			continue
		}
		if !strings.Contains(lower, "setup") && !strings.Contains(lower, "install") {
			continue
		}
		cands = append(cands, filepath.Join(root, name))
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		si, _ := os.Stat(cands[i])
		sj, _ := os.Stat(cands[j])
		var a, b int64
		if si != nil {
			a = si.Size()
		}
		if sj != nil {
			b = sj.Size()
		}
		return a > b
	})
	return cands[0]
}

// ExtractFirefoxFromInstaller 把安装包里的 core/ 提取为 Surf/Firefox。
// 先解到临时目录、验明 firefox 本体在，再换到位，失败不破坏已有浏览器。
// progress 按解出字节上报 0-100（提取要几分钟，没有进度看着像死机）。
func ExtractFirefoxFromInstaller(installer, root string, progress func(pct int)) error {
	dst := filepath.Join(surfDir(root), "Firefox")
	tmp := filepath.Join(surfDir(root), "tmp", "ffx-extract")
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	r, err := sevenzip.OpenReader(installer)
	if err != nil {
		return fmt.Errorf("安装包打不开（不是官方完整版安装包？）：%v", err)
	}
	defer r.Close()

	// 先算 core/ 的总字节数，进度才有分母
	var total int64
	for _, f := range r.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		name = strings.TrimPrefix(name, "./")
		if !f.FileInfo().IsDir() && strings.HasPrefix(name, "core/") {
			total += int64(f.UncompressedSize) //nolint:gosec
		}
	}
	rep := newPctReporter(total, progress)

	found := false
	for _, f := range r.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		name = strings.TrimPrefix(name, "./")
		if f.FileInfo().IsDir() || strings.HasSuffix(name, "/") {
			continue
		}
		if !strings.HasPrefix(name, "core/") {
			continue // 安装包根目录的 setup.exe 等安装器文件不要
		}
		rel := strings.TrimPrefix(name, "core/")
		target := filepath.Join(tmp, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, filepath.Clean(tmp)+string(os.PathSeparator)) {
			return fmt.Errorf("安装包里有异常路径")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("提取 %s 失败：%v", rel, err)
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(w, &progressReader{r: rc, onBytes: rep.add})
		rc.Close()
		w.Close()
		if err != nil {
			return fmt.Errorf("提取 %s 失败：%v", rel, err)
		}
		if strings.EqualFold(rel, "firefox.exe") {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("安装包里没有 core\\firefox.exe——这多半是在线安装包（只有几百 KB），请改用官方完整版安装包（约 90MB）")
	}
	// 换到位：旧的先挪走，新的顶上，再删旧的
	bak := dst + ".old"
	_ = os.RemoveAll(bak)
	if fileExists(dst) {
		if err := os.Rename(dst, bak); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(bak, dst)
		return err
	}
	_ = os.RemoveAll(bak)
	return nil
}

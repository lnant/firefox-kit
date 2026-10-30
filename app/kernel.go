package main

// sing-box 内核管理：按需下载（只在用到 B/C 类节点时）、官方来源、
// 校验、更新（先验新版再换、旧版留备份可退回）。内核是外置组件，不内嵌。

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func coreDir(root string) string     { return filepath.Join(surfDir(root), "core") }
func singboxName() string            { return binName("sing-box") }
func singboxPath(root string) string { return filepath.Join(coreDir(root), singboxName()) }
func singboxBak(root string) string  { return singboxPath(root) + ".bak" }

func KernelReady(root string) bool { return fileExists(singboxPath(root)) }

// AdoptLooseKernel 收编放在工具根目录的内核文件：用户按“文件都放一个
// 文件夹”的直觉把 sing-box.exe 摆在根目录时，程序自动把它（连同
// libcronet）复制进 Surf/core，不让人白放。已就位时不动，返回是否收编过。
func AdoptLooseKernel(root string) bool {
	if KernelReady(root) {
		return false
	}
	src := filepath.Join(root, singboxName())
	if !fileExists(src) {
		return false
	}
	if err := os.MkdirAll(coreDir(root), 0o755); err != nil {
		return false
	}
	if err := copyFileSimple(src, singboxPath(root)); err != nil {
		return false
	}
	for _, extra := range []string{"libcronet.dll", "libcronet.so"} {
		if p := filepath.Join(root, extra); fileExists(p) {
			_ = copyFileSimple(p, filepath.Join(coreDir(root), extra))
		}
	}
	return KernelReady(root)
}

func KernelVersion(root string) string {
	p := singboxPath(root)
	if !fileExists(p) {
		return ""
	}
	out, err := execCommand(p, "version")
	if err != nil {
		return ""
	}
	// 输出首行形如：sing-box version 1.14.4
	line := firstLine(out)
	f := strings.Fields(line)
	if len(f) >= 3 {
		return f[2]
	}
	return ""
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// LatestKernelRelease 查 sing-box 官方 GitHub 最新版及当前平台的安装包。
func LatestKernelRelease(ctx context.Context) (version, assetName, assetURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", "foxkit/1.0")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("连不上 GitHub：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", "", fmt.Errorf("GitHub 返回 HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&rel); err != nil {
		return "", "", "", err
	}
	ver := strings.TrimPrefix(rel.TagName, "v")
	want := fmt.Sprintf("sing-box-%s-%s-%s", ver, runtime.GOOS, runtime.GOARCH)
	for _, a := range rel.Assets {
		if strings.HasPrefix(a.Name, want) && (strings.HasSuffix(a.Name, ".zip") || strings.HasSuffix(a.Name, ".tar.gz")) {
			return ver, a.Name, a.URL, nil
		}
	}
	return "", "", "", fmt.Errorf("最新版 %s 里没有当前平台（%s/%s）的安装包", ver, runtime.GOOS, runtime.GOARCH)
}

// DownloadKernel 下载并安装 sing-box 到 Surf/core。已有内核时先备份为 .bak。
// progress 回调 0-100（下载阶段）；解压校验阶段回调 -1 表示忙碌不定量。
func DownloadKernel(ctx context.Context, root string, progress func(pct int)) error {
	_, assetName, assetURL, err := LatestKernelRelease(ctx)
	if err != nil {
		return err
	}
	tmpDir := filepath.Join(surfDir(root), "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(coreDir(root), 0o755); err != nil {
		return err
	}
	archive := filepath.Join(tmpDir, assetName)
	if err := downloadFile(ctx, assetURL, archive, progress); err != nil {
		return err
	}
	if progress != nil {
		progress(-1)
	}
	extractDir := filepath.Join(tmpDir, "kernel-extract")
	_ = os.RemoveAll(extractDir)
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(extractDir)
	if strings.HasSuffix(assetName, ".zip") {
		err = extractZip(archive, extractDir)
	} else {
		err = extractTarGz(archive, extractDir)
	}
	if err != nil {
		return fmt.Errorf("安装包解压失败：%v", err)
	}
	// 在解压结果里找 sing-box 本体（可能带一层版本目录）
	var binSrc, cronetSrc string
	_ = filepath.Walk(extractDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		switch info.Name() {
		case singboxName():
			binSrc = p
		case "libcronet.dll", "libcronet.so":
			cronetSrc = p
		}
		return nil
	})
	if binSrc == "" {
		return fmt.Errorf("安装包里没找到 sing-box 程序")
	}
	dst := singboxPath(root)
	if fileExists(dst) {
		_ = copyFileSimple(dst, singboxBak(root)) // 旧版留底，可退回
	}
	tmpDst := dst + ".new"
	if err := copyFileSimple(binSrc, tmpDst); err != nil {
		return err
	}
	_ = os.Chmod(tmpDst, 0o755)
	if err := os.Rename(tmpDst, dst); err != nil {
		_ = os.Remove(tmpDst)
		return err
	}
	if cronetSrc != "" {
		_ = copyFileSimple(cronetSrc, filepath.Join(coreDir(root), filepath.Base(cronetSrc)))
	}
	if v := KernelVersion(root); v == "" {
		// 新内核跑不起来：自动退回旧版
		if fileExists(singboxBak(root)) {
			_ = copyFileSimple(singboxBak(root), dst)
			return fmt.Errorf("新下载的内核无法运行，已退回上一个版本")
		}
		return fmt.Errorf("新下载的内核无法运行")
	}
	return nil
}

// RollbackKernel 把内核退回上一个备份版本。
func RollbackKernel(root string) error {
	if !fileExists(singboxBak(root)) {
		return fmt.Errorf("没有可退回的内核备份")
	}
	cur := singboxPath(root)
	tmp := cur + ".cur"
	if fileExists(cur) {
		_ = copyFileSimple(cur, tmp)
	}
	if err := copyFileSimple(singboxBak(root), cur); err != nil {
		return err
	}
	if fileExists(tmp) {
		_ = copyFileSimple(tmp, singboxBak(root))
		_ = os.Remove(tmp)
	}
	return nil
}

func downloadFile(ctx context.Context, url, dst string, progress func(pct int)) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "foxkit/1.0")
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("下载失败：服务器返回 HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	var written int64
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			written += int64(n)
			if progress != nil && resp.ContentLength > 0 {
				progress(int(written * 100 / resp.ContentLength))
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func extractZip(archive, dst string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		target := filepath.Join(dst, f.Name)
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("安装包里有异常路径")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(w, rc)
		rc.Close()
		w.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(archive, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, h.Name)
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("安装包里有异常路径")
		}
		if h.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return err
		}
		w.Close()
	}
}

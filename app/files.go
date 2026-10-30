package main

import (
	"io"
	"os"
	"path/filepath"
)

// progressReader 读一点报一点：长耗时操作靠它驱动进度条，
// 免得用户分不清是在跑还是死机。
type progressReader struct {
	r       io.Reader
	onBytes func(n int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && p.onBytes != nil {
		p.onBytes(int64(n))
	}
	return n, err
}

// pctReporter 把累计字节数换算成百分比，只在百分比变化时才回调，不刷屏。
type pctReporter struct {
	total   int64
	done    int64
	lastPct int
	onPct   func(pct int)
}

func newPctReporter(total int64, onPct func(pct int)) *pctReporter {
	return &pctReporter{total: total, lastPct: -1, onPct: onPct}
}

func (p *pctReporter) add(n int64) {
	p.done += n
	if p.onPct == nil || p.total <= 0 {
		return
	}
	pct := int(p.done * 100 / p.total)
	if pct > 100 {
		pct = 100
	}
	if pct != p.lastPct {
		p.lastPct = pct
		p.onPct(pct)
	}
}

// copyDir 递归复制目录（组装便携浏览器时把本机 Firefox 程序目录搬进工具包）。
func copyDir(src, dst string) error {
	return copyDirProgress(src, dst, nil)
}

// copyDirProgress 同 copyDir，但按字节上报进度 0-100。
func copyDirProgress(src, dst string, progress func(pct int)) error {
	var total int64
	_ = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	rep := newPctReporter(total, progress)
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, &progressReader{r: in, onBytes: rep.add})
		return err
	})
}

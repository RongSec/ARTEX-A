package vulnintel

// 单源手动触发的导出包装。
//
// 为什么需要：库配置页每行都有「立即同步」按钮，只能触发某一个源；而同步器
// 内部的 syncKEV / syncNVD / syncPoCs 是包私有的。这里做一层薄包装，不复制
// 逻辑——否则两条路径迟早漂移。

import (
	"context"
	"log"
	"time"
)

// SyncKEVOnly 只跑 KEV（单个 JSON，最廉价）。
func (s *Store) SyncKEVOnly(ctx context.Context, cfg Config) error {
	if cfg.PageDelay <= 0 {
		cfg.PageDelay = PageDelayFor(cfg.NvdAPIKey)
	}
	return syncKEV(ctx, s, cfg)
}

// SyncNVDWindow 按给定时间窗跑一轮 NVD（lastModifiedDate 维度）。
// 窗口超过 120 天需要调用方自己切——NVD 的 API 契约上限就是 120 天。
func (s *Store) SyncNVDWindow(ctx context.Context, cfg Config, since, until time.Time) error {
	if cfg.PageDelay <= 0 {
		cfg.PageDelay = PageDelayFor(cfg.NvdAPIKey)
	}
	if cfg.MaxRuntime <= 0 {
		cfg.MaxRuntime = 30 * time.Minute
	}
	deadline := time.Now().Add(cfg.MaxRuntime)
	if d, ok := ctx.Deadline(); !ok || d.After(deadline) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	return syncNVDRange(ctx, s, cfg, since, until)
}

// BackfillNVD 从「N 天前」补到今天；days<=0 表示从最早开始（由游标推进）。
func (s *Store) BackfillNVD(ctx context.Context, cfg Config, days int) error {
	if days < 0 {
		days = 0
	}
	until := time.Now()
	since := time.Time{}
	if days > 0 {
		since = until.AddDate(0, 0, -days)
	}
	return s.SyncNVDWindow(ctx, cfg, since, until)
}

// SyncPoCOnly 只跑 PoC 聚合（GitHub 搜索，受配额限制）。
func (s *Store) SyncPoCOnly(ctx context.Context, cfg Config) error {
	return syncPoCs(ctx, s, cfg)
}

// syncNVDRange 按给定窗口补 NVD，**不动主同步游标**。
//
// 为什么不动：手动补历史（比如只补 2021 年）不应把 lastModified 增量游标
// 推到那个时间点——一推，下次增量就从两年前开始重扫。
func syncNVDRange(ctx context.Context, st *Store, cfg Config, since, until time.Time) error {
	client, err := NewNvdClient(cfg.NvdAPIKey, cfg.ProxyURL)
	if err != nil {
		return err
	}
	if since.IsZero() {
		since = time.Date(1988, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if !until.After(since) {
		return nil
	}
	state, err := st.GetSyncState(ctx, "nvd")
	if err != nil {
		return err
	}
	total := 0
	for winStart := since; winStart.Before(until); {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		winEnd := winStart.AddDate(0, 0, 120)
		if winEnd.After(until) {
			winEnd = until
		}
		n, werr := syncNVDWindow(ctx, client, st, winStart, winEnd, cfg.PageDelay, 0, &state)
		total += n
		if werr != nil {
			state.LastError = werr.Error()
			_ = st.SaveSyncState(ctx, state)
			return werr
		}
		log.Printf("[vulnintel] nvd 手动窗口 %s ~ %s: %d 条",
			winStart.Format("2006-01-02"), winEnd.Format("2006-01-02"), n)
		winStart = winEnd
	}
	state.LastError = ""
	state.TotalSynced += int64(total)
	return st.SaveSyncState(ctx, state)
}

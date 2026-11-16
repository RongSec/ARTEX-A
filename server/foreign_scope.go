package server

import (
	"context"
	"errors"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
)

// taskScopeResolver 是 guard.ScopeResolver 的生产实现：外部 host 来自
// task_foreign_assets（阅读者采纳时写入），本任务 host 来自 assets.task_ids。
//
// 查询失败一律向上返回 error，由 guard 放行（宁漏不误伤）；这里不做任何
// 静默兜底，避免把「查不到」误当成「没有外部资产」以外的第二层判断。
type taskScopeResolver struct {
	pg     *db.DB
	assets *db.AssetStore
}

func (r taskScopeResolver) ForeignHosts(ctx context.Context, taskID int64) ([]string, error) {
	return r.pg.ForeignHostsForTask(ctx, taskID)
}

func (r taskScopeResolver) OwnHosts(ctx context.Context, taskID int64) ([]string, error) {
	if r.assets == nil {
		return nil, errors.New("asset store unavailable")
	}
	return r.assets.HostsByTask(taskID)
}

// newTaskGuard 构造带内置外部资产范围规则的 Guard。所有任务/聊天 Guard 都
// 必须经这里，否则 V9-SCOPE 执行层对它们不生效。
func (s *Server) newTaskGuard() *guard.Guard {
	g := guard.NewWithInterceptor(s.m.interceptor)
	g.SetScopeResolver(taskScopeResolver{pg: s.m.pg, assets: s.m.assets})
	return g
}

// newPlannerGuard 是只跑内置外部资产范围规则的 Guard（规划者专用）。
// 规划者在 V9-SCOPE 前不挂任何 hooks；接完整规则表会让 add_intent 正文里的
// rm -rf / 凭据路径被误拦。这里只补跨任务资产边界这一条。
func (s *Server) newPlannerGuard() *guard.Guard {
	g := guard.NewWithInterceptor(s.m.interceptor)
	g.SetScopeResolver(taskScopeResolver{pg: s.m.pg, assets: s.m.assets})
	g.SetScopeOnly(true)
	return g
}

// guardForManager 是 taskFromPG 用的包级版本（Manager 初始化阶段还没有 *Server）。
func guardForManager(m *Manager, ic *intercept.Interceptor) *guard.Guard {
	g := guard.NewWithInterceptor(ic)
	g.SetScopeResolver(taskScopeResolver{pg: m.pg, assets: m.assets})
	return g
}

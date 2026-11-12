package server

import (
	"log"
	"sync"

	"github.com/Autumn-27/artex/db"
)

// T18（N2）：整项目收官自动写报告。
//
// 挂点=Manager.OnTaskTerminal（nil 短路，由 installAutoReportHook 在 server.New
// 的 PG 就绪分支装配）。任务终态 → 查所属项目 auto_report → 去抖（项目还有
// 未终态任务=还没收官，跳过）→ 整项目收官 → 建 project 级报告 job（复用
// reportgen.go 的 InsertReport + runReportJob 状态机，与手动 /api/report/generate
// 同一管道）。
//
// 整条链路是旁路增强（照 reproEnricherFor 的纪律）：任何失败只 log 一行，
// 绝不回抛——任务终态早已提交，这里做的是「之后尽力出报告」。emitTaskTerminal
// 外层已 recover，本文件函数内的 DB 错误全部就地吞掉记日志。

// settingAutoReportEnabled 是全局应急闸（db settings，默认开）。项目级开关
// auto_report 是 opt-in，此闸用于「出报告管道整体拖垮系统」时一键全关，
// 不用挨个项目取消勾选。
const settingAutoReportEnabled = "auto_report_enabled"

// projectSettled 判定「项目是否已收官」：submittedTaskIDs 是项目内全部存活任务，
// terminalIDs 是其中已落终态的集合。纯函数（查库在调用方），单测覆盖四种形态：
// 无项目 / auto 关时根本不会调到这里（调用方先短路）/ 部分终态=未收官 / 全终态=收官。
//
// 语义细节：刚 emit 的那个任务必然已在 terminalIDs（emit 前 DB 已写终态）；
// 项目内 0 个任务不算收官（空项目没有「报告」可言，也防误触）。
func projectSettled(all, terminal map[int64]bool) (settled bool, taskCount int) {
	if len(all) == 0 {
		return false, 0
	}
	for id := range all {
		if !terminal[id] {
			return false, len(all)
		}
	}
	return true, len(all)
}

// installAutoReportHook 装配终态钩子（仅 server.New 的 PG 非空分支调用一次）。
func (s *Server) installAutoReportHook() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	s.m.OnTaskTerminal = s.onTaskTerminalAutoReport
}

// onTaskTerminalAutoReport 是钩子实现。入参可能来自任意任务（含无项目任务），
// 前三个短路条件把 99% 的派发挡在最便宜的检查上：全局闸 → 任务有项目 →
// 项目 auto_report。查库用独立 ctx（钩子在后台协程里跑，s.ctx 取消=进程退出，
// 此时查询自然失败、就地吞掉即可）。
func (s *Server) onTaskTerminalAutoReport(taskID int64, status string) {
	pg := s.m.pg
	if !pg.GetBool(settingAutoReportEnabled, true) {
		return
	}
	t, err := pg.GetTask(taskID)
	if err != nil {
		log.Printf("[auto-report] task %d 读取失败: %v", taskID, err)
		return
	}
	if t == nil || t.ProjectID == nil || *t.ProjectID <= 0 {
		return // 无项目=原版路径，零行为
	}
	pid := *t.ProjectID
	p, err := pg.GetProject(pid)
	if err != nil {
		log.Printf("[auto-report] project %d 读取失败: %v", pid, err)
		return
	}
	if p == nil || !p.AutoReport {
		return // 项目开关默认关=基线
	}
	s.settleProjectAndReport(pid, taskID, status, p.ReportTemplateID)
}

// autoReportLockFor 取项目级互斥锁（sync.Map load-or-store，锁本身永不删除——
// 项目是人工建的分组单位，数量有界）。
func (m *Manager) autoReportLockFor(projectID int64) *sync.Mutex {
	if v, ok := m.autoReportMu.Load(projectID); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := m.autoReportMu.LoadOrStore(projectID, mu)
	return actual.(*sync.Mutex)
}

// settleProjectAndReport 在**项目级互斥**内完成「查收官→查在途→建 job」：
//
// 并发双终态（项目最后两个任务几乎同时收官）时，两个钩子协程都可能查到
// 全终态；互斥把这段判定串行化，后到者再经 HasOpenProjectReport 看到前者
// 刚入队的 pending/running job 即跳过——本进程内不重复。跨进程重启的极端
// 窗口（上次进程建的 job 已 done、新进程再次派发）不在本期范围：终态任务
// 重启后不会再 emit（钩子只在状态转换成功时派发）。
func (s *Server) settleProjectAndReport(pid, taskID int64, status string, boundTemplate *int64) {
	pg := s.m.pg
	mu := s.m.autoReportLockFor(pid)
	mu.Lock()
	defer mu.Unlock()

	// 去抖：项目内还有未终态的存活任务 → 整个项目还没收官，跳过。
	// emit 发生在终态 DB 写成功之后，所以「最后一个收官者」必然能查到
	// 全部任务已终态。
	tasks, err := pg.ProjectTasks(pid)
	if err != nil {
		log.Printf("[auto-report] project %d 任务列表失败: %v", pid, err)
		return
	}
	all := make(map[int64]bool, len(tasks))
	terminal := make(map[int64]bool, len(tasks))
	var taskIDs []int64
	for _, x := range tasks {
		all[x.ID] = true
		taskIDs = append(taskIDs, x.ID)
		if db.IsTerminal(x.Status) {
			terminal[x.ID] = true
		}
	}
	if settled, _ := projectSettled(all, terminal); !settled {
		log.Printf("[auto-report] task %d(%s) 终态，但项目 %d 尚有未终态任务，跳过", taskID, status, pid)
		return
	}
	// 并发双终态去重：持锁后若项目已有 pending/running 的 project 级 job，
	// 说明并行的另一个钩子刚完成入队，直接跳过。
	if open, err := pg.HasOpenProjectReport(pid); err != nil {
		log.Printf("[auto-report] project %d 在途 job 检查失败: %v", pid, err)
		return
	} else if open {
		log.Printf("[auto-report] project %d 已有在途自动报告 job，跳过", pid)
		return
	}

	// 收官 → 建 project 级报告 job。无 findings 不出报告（照手动管道 :435-438
	// 的「无米之炊不进队列」语义）。
	fs, err := pg.FindingsForReport(taskIDs, nil)
	if err != nil {
		log.Printf("[auto-report] project %d findings 读取失败: %v", pid, err)
		return
	}
	if len(fs) == 0 {
		log.Printf("[auto-report] project %d 已收官但无漏洞发现，跳过报告", pid)
		return
	}
	// 模板解析链：项目绑定 → settings → is_default（ResolveTemplateIDBySettings
	// 的 0 值语义现成；绑定行被删时同样回退，返回 nil=全默认骨架渲染）。
	explicit := int64(0)
	if boundTemplate != nil && *boundTemplate > 0 {
		explicit = *boundTemplate
	}
	tmpl, err := pg.ResolveTemplateIDBySettings(explicit)
	if err != nil {
		log.Printf("[auto-report] project %d 模板解析失败: %v", pid, err)
		return
	}
	tmplID := int64(0)
	locale := ""
	if tmpl != nil {
		tmplID = tmpl.ID
		locale = tmpl.OutputLang
	}
	if locale == "" {
		if st, err := pg.GetReportSettings(); err == nil {
			locale = st.DefaultLocale
		}
	}
	findIDs := make([]int64, 0, len(fs))
	for _, f := range fs {
		findIDs = append(findIDs, f.ID)
	}
	job, err := pg.InsertReport(db.ReportScopeProject, 0, pid, tmplID, locale, "docx", findIDs)
	if err != nil {
		log.Printf("[auto-report] project %d 建报告 job 失败: %v", pid, err)
		return
	}
	log.Printf("[auto-report] project %d 全部 %d 个任务收官，自动报告 job %d 已入队", pid, len(taskIDs), job.ID)
	// runReportJob 内部自带 panic 兜底 + 状态机收尾，但它在**当前协程**推进；
	// 这里再 go 一层，钩子协程立刻归还。
	go s.runReportJob(job)
}

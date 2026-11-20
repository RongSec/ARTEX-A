package server

// worker 的阅读者下钻工具绑定（V11-WORKER-READER）。
//
// 为什么需要迁移：tools 表是首插入 only（SeedTool ON CONFLICT DO NOTHING），
// 老库的 ask_reader 行只绑了 planner。代码里把 ask_reader 加进 WorkerTools()
// 只对全新库有效；存量库必须在启动时补一次 worker 绑定，否则 ToolResolve
// 会按 tools 表的 agents 把它从 worker 工具集里丢掉。
//
// settings flag 守卫 → 只做一次；用户之后在工具页手动解绑不会被反复覆盖。

import "log"

const workerAskReaderFlag = "worker_ask_reader_binding_v1"

func (s *Server) seedWorkerReaderTools() {
	if v, _, _ := s.m.pg.GetSetting(workerAskReaderFlag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{"ask_reader"}); err != nil {
		log.Printf("[tools] ask_reader 绑定 worker 失败: %v", err)
		return
	}
	if err := s.m.pg.SetSetting(workerAskReaderFlag, "true"); err != nil {
		log.Printf("[tools] 记录 worker_ask_reader 迁移标记失败: %v", err)
		return
	}
	log.Printf("[tools] ask_reader 已绑定 worker（只读经验下钻，host 由工具层拦截）")
}

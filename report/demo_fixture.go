package report

// T20（N1-D）demo fixture：内置样例报告输入，供报告中心「对话调模板+实时预览」
// 与 demo 调试通道使用。**旁路 DB**——不建 demo 任务/findings 行（设计 §1.2D：
// FindingsForReport 以 task_id 为硬谓词、存在性校验要真实任务行，走 demo 任务
// 会污染任务列表/统计/投影事件流）。3 条虚构漏洞（critical 未授权/high SQLi/
// medium XSS），域名统一 demo.example.com、报文逐字但全假（明显虚构的口令/
// Cookie/token），无证据图。
//
// 红线：fixture 的伪资产校验（FilterPseudoTargets）在 demo 通道由调用方显式
// 跳过（targets 自洽即可，校验针对真实交付）——见 server 侧装配注释。

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/db"
)

//go:embed demo/report-input.json
var demoInputJSON []byte

// demoInputCache 解析一次即用（fixture 静态不变；解析失败=开发期 bug，宁可
// panic 在 init 也别让运行期每次渲染吞错）。
var demoInputCache = mustParseDemo()

func mustParseDemo() *ReportInput {
	var in ReportInput
	if err := json.Unmarshal(demoInputJSON, &in); err != nil {
		panic(fmt.Sprintf("report: invalid demo fixture: %v", err))
	}
	if len(in.Findings) == 0 {
		panic("report: demo fixture has no findings")
	}
	return &in
}

// DemoInput 返回一份**新的**样例报告输入（深拷贝——调用方可能就地改
// GeneratedAt/元字段，不得污染缓存）。Chapters 用默认骨架（与 fixture JSON
// 内的章节列表一致），server 装配时按模板 skeleton/style 覆盖元字段。
func DemoInput() *ReportInput {
	cp := *demoInputCache
	cp.Chapters = append([]db.ReportSection(nil), demoInputCache.Chapters...)
	cp.Tasks = append([]TaskMeta(nil), demoInputCache.Tasks...)
	cp.Targets = append([]string(nil), demoInputCache.Targets...)
	cp.Findings = append([]VulnSection(nil), demoInputCache.Findings...)
	for i := range cp.Findings {
		cp.Findings[i].SourceTasks = append([]int64(nil), demoInputCache.Findings[i].SourceTasks...)
	}
	return &cp
}

// DemoInputRaw 返回 fixture 原始 JSON（前端/测试直读形态时用）。
func DemoInputRaw() []byte { return demoInputJSON }

// demoGeneratedAt 每次 demo 渲染刷新生成时间（缓存里的时间戳是编写期的）。
func DemoTouchGeneratedAt(in *ReportInput) { in.GeneratedAt = time.Now() }

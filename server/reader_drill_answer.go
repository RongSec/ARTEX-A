package server

// 阅读者下钻总结（V10-READER）：把 ask_reader 取到的脱敏证据交给阅读者角色，
// 由它总结成「接口测试方法论」再回给规划者。
//
// 为什么要有这一步：确定性脱敏只能给「它当时发了什么包」，规划者拿到一堆
// 请求行还得自己归纳；用户要的是阅读者代劳——告诉它「这类接口该怎么测、
// 验什么、什么响应算命中」。这一步是阅读者唯一的模型调用，输入已脱敏，
// 输出再过一遍脱敏（防模型把 host 从上下文里"补"回来）。
//
// 模型跟随任务的 reader 角色（readerRuntime）：没有 reader 绑定时按任务链回退；
// llm_records 会记成 worker=reader，任务页的「阅读者审计」能看到这次下钻。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/redact"
	"github.com/Autumn-27/norma/llm"
)

const readerDrillSystemPrompt = `你是渗透测试平台的【阅读者】：只读、只总结，不执行任何动作。
当前任务的规划者在测一个系统，遇到与历史任务同构的接口/组件，向你下钻参考任务的测试证据。
你的任务：把证据归纳成【接口测试方法论】，供规划者在自己的授权目标上验证。

输出要求：
1. 只讲「怎么测」：请求构造（方法/路径/参数/payload 形态）、前置条件（登录态/角色/凭据类型）、验证步骤、判据（什么响应/状态码/回显算命中）、常见坑。
2. 不要出现任何 host、IP、域名、端口、凭据明文；原文里的占位符（<host>/<ip>/<redacted>）保持原样，不要猜测还原。
3. 区分「已验证」与「推测」：证据里明确成功的写「已验证」，只是同类推断的写「待验证」。
4. 简洁：最多 8 条要点，每条一行；不要复述证据原文，不要写客套话。
5. 如果证据不足以形成方法，直接说「证据不足：缺少 X」，不要编造。`

const readerDrillWorkerPrompt = `你是渗透测试平台的【阅读者】：只读、只总结，不执行任何动作。
当前任务的执行者领到了一条具体意图（例如“测试 /api/xxx 接口”），向你下钻参考任务的测试证据。
它拿不到（也不允许拿）参考任务的 host/IP；它需要的是「怎么在这个接口上复现同类测试」。

输出要求：
1. 只讲执行者能直接照做的东西：请求方法/路径、参数与 payload 形态、前置条件（登录态/角色/凭据类型）、逐步验证动作、判据（状态码/响应差异/回显）、常见坑。
2. 不要出现任何 host、IP、域名、端口、凭据明文；占位符（<host>/<ip>/<redacted>）保持原样，不要猜。
3. 不要下「本任务存在该漏洞」的结论；参考任务已验证的写「参考任务已验证」，推断的写「待验证」。
4. 结合当前意图裁剪：只保留与它要测的接口/组件相关的步骤；最多 8 条，每条一行，不要客套。
5. 证据不足以形成可执行步骤时，直接说「证据不足：缺少 X」，不要编造。`

// readerDrillAnswer 是 Planner.SetReaderAnswer 的实现：一次同步补全，失败即如实报错
// （ask_reader 会退回脱敏证据，不会因此让规划者这一轮失败）。
func (s *Server) readerDrillAnswer(ctx context.Context, rt *taskLLMRuntime, req agent.ReaderDrillRequest) (string, error) {
	if rt == nil {
		return "", errors.New("阅读者模型未配置")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	sys := readerDrillSystemPrompt
	if req.Audience == "worker" {
		sys = readerDrillWorkerPrompt
	}
	user := "参考任务 #" + fmt.Sprint(req.RelatedTaskID) + " 的下钻证据（已脱敏）：\n" + string(payload)
	if g := strings.TrimSpace(req.CurrentGoal); g != "" {
		user += "\n\n当前任务目标：" + g
	}
	if it := strings.TrimSpace(req.CurrentIntent); it != "" {
		user += "\n当前执行者领到的意图：" + it
	}
	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// 把这条调用标成 reader 通道：llm_records.worker=reader，任务页的
	// 「阅读者审计」runs 才会出现这次下钻（否则按无会话调用记成空 lane）。
	callCtx = llmrec.WithWorker(callCtx, "reader")
	msg, _, _, err := rt.Complete(callCtx, llm.CompletionRequest{
		System: []string{sys},
		Messages: []llm.Message{
			llm.UserText(user),
		},
		MaxTokens: 1200,
		Thinking:  "disabled", // 归纳任务，不需要思维链
	})
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(msg.Text())
	if out == "" {
		return "", errors.New("阅读者返回空内容")
	}
	// 输出侧再脱敏一次：模型可能从证据上下文里把占位符"还原"成具体 host。
	return redact.TestMethod(out), nil
}

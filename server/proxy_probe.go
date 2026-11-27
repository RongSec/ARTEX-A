package server

// 代理连通性测试：系统配置页的「全局代理 / 上网代理」两个测试按钮共用。
//
// 只做一件事：用页面上**当前输入**的代理（未保存也能测）请求用户给的目标，
// 返回是否拿到 HTTP 响应、状态码、耗时与错误。区别于「测试连通性」那种按
// 源逐个探测的接口——这里测的是代理本身，目标可自定义。
//
// 安全：仅登录后的管理端可调用（挂在 /api/settings 下）。测试目标由操作员
// 输入，属于渗透平台自身的出口诊断，不做额外 SSRF 白名单。

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type proxyTestReq struct {
	Proxy  string `json:"proxy"`
	Target string `json:"target"`
}

type proxyTestResp struct {
	OK        bool   `json:"ok"`
	Target    string `json:"target"`
	Proxy     string `json:"proxy,omitempty"`
	Status    int    `json:"status,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Snippet   string `json:"snippet,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) proxyTest(w http.ResponseWriter, r *http.Request) {
	var req proxyTestReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = "https://www.baidu.com"
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		writeErr(w, 400, "测试目标无效，示例：https://www.baidu.com")
		return
	}

	proxy := strings.TrimSpace(req.Proxy)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // 留空=直连，不回落环境变量里的 HTTP_PROXY
	if proxy != "" {
		pu, err := url.Parse(proxy)
		if err != nil {
			writeErr(w, 400, "代理地址无效："+err.Error())
			return
		}
		switch strings.ToLower(pu.Scheme) {
		case "http", "https", "socks5", "socks5h":
			transport.Proxy = http.ProxyURL(pu)
		case "":
			writeErr(w, 400, "代理地址缺少协议头，示例：http://host:port 或 socks5://host:1080")
			return
		default:
			writeErr(w, 400, "不支持的代理协议："+pu.Scheme+"（支持 http/https/socks5）")
			return
		}
	}
	// 测试只关心「能不能通」，不校验目标证书（内网自签站点很常见）。
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向次数过多")
			}
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Get(target)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, 200, proxyTestResp{
			OK: false, Target: target, Proxy: proxy, ElapsedMS: elapsed,
			Error: err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
	snippet := strings.TrimSpace(string(body))
	if len([]rune(snippet)) > 160 {
		snippet = string([]rune(snippet)[:160]) + "…"
	}
	// 任何 HTTP 响应都说明代理链路是通的（401/403 也可能是目标要求认证）。
	writeJSON(w, 200, proxyTestResp{
		OK: true, Target: target, Proxy: proxy,
		Status: resp.StatusCode, ElapsedMS: elapsed, Snippet: snippet,
	})
}

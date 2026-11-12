package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestParseBatchFindingIDs 覆盖去重、数字/字符串兼容、非法值分流（无库纯函数）。
func TestParseBatchFindingIDs(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`1`),
		json.RawMessage(`"2"`),
		json.RawMessage(`1`),
		json.RawMessage(`"3 "`),
		json.RawMessage(`0`),
		json.RawMessage(`-4`),
		json.RawMessage(`"abc"`),
		json.RawMessage(`null`),
	}
	ids, invalid := parseBatchFindingIDs(raw)
	if len(ids) != 3 || ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("dedupe/parse broken: %v", ids)
	}
	// 非法四条：0、-4、"abc"、null（json null 解为字符串时是空串）。
	if len(invalid) != 4 || invalid[0] != "0" || invalid[1] != "-4" || invalid[2] != "abc" || invalid[3] != "" {
		t.Fatalf("invalid bucketing broken: %q", invalid)
	}
	empty, emptyInvalid := parseBatchFindingIDs(nil)
	if len(empty) != 0 || len(emptyInvalid) != 0 {
		t.Fatal("nil input must yield empty buckets")
	}
}

// postBatchStatus 直连 handler 发请求（校验路径在触库前返回，零值 Server 即可）。
func postBatchStatus(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/api/exploration/findings/batch-status", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.findingsBatchStatus(w, r)
	return w
}

// TestFindingsBatchStatusValidation 覆盖无库即可判定的入参校验：
// 空 ids、超上限、非法 status、非法 json 全部 400。
func TestFindingsBatchStatusValidation(t *testing.T) {
	if w := postBatchStatus(t, `{"ids":[],"status":"confirmed"}`); w.Code != 400 {
		t.Fatalf("empty ids: %d %s", w.Code, w.Body)
	}
	over := make([]string, maxBatchFindingIDs+1)
	for i := range over {
		over[i] = fmt.Sprintf("%d", i+1)
	}
	if w := postBatchStatus(t, fmt.Sprintf(`{"ids":[%s],"status":"confirmed"}`, strings.Join(over, ","))); w.Code != 400 {
		t.Fatalf("over limit: %d %s", w.Code, w.Body)
	}
	if w := postBatchStatus(t, `{"ids":[1],"status":"not_a_status"}`); w.Code != 400 {
		t.Fatalf("bad status: %d %s", w.Code, w.Body)
	}
	if w := postBatchStatus(t, `{`); w.Code != 400 {
		t.Fatalf("bad json: %d %s", w.Code, w.Body)
	}
}

// TestFindingsBatchStatusNotFound 验证部分失败保持 200、不存在/非法 id 如实回报
// （需 PG，无库 skip）。
func TestFindingsBatchStatusNotFound(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// handler 只依赖 m.pg，构造最小 Manager 即可。
	s := &Server{m: &Manager{pg: pg}}

	// 找一条真实存在的漏洞做正向样本；库里没有则只验证 not_found 路径。
	var realID int64
	_ = pg.QueryRow(`SELECT id FROM findings ORDER BY id LIMIT 1`).Scan(&realID)
	missing := int64(900000000000000000)

	body := fmt.Sprintf(`{"ids":[%d,%d,"bad"],"status":"pending"}`, missing, realID)
	r := httptest.NewRequest(http.MethodPost, "/api/exploration/findings/batch-status", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.findingsBatchStatus(w, r)
	if w.Code != 200 {
		t.Fatalf("partial failure must stay 200: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Updated  []int64  `json:"updated"`
		NotFound []string `json:"not_found"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err, w.Body)
	}
	if resp.NotFound == nil {
		t.Fatal("not_found must serialize as [] not null")
	}
	reported := strings.Join(resp.NotFound, ",")
	if !strings.Contains(reported, fmt.Sprint(missing)) {
		t.Fatalf("missing id not reported: %v", resp.NotFound)
	}
	if !strings.Contains(reported, "bad") {
		t.Fatalf("malformed id not reported: %v", resp.NotFound)
	}
	if realID > 0 {
		inUpdated := false
		for _, id := range resp.Updated {
			if id == realID {
				inUpdated = true
			}
		}
		if !inUpdated {
			t.Fatalf("real finding missing from updated: %v", resp.Updated)
		}
	}
}

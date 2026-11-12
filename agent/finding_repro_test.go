package agent

// T14(2/2) report_finding → ReproEnricher 派发契约测（需 PG，无库自动 skip）：
//  1. 带非空 steps 的 reproduction 落库【成功】后，enricher 在【后台协程】被
//     调到、且拿到正确的 findingID/taskID/repro 原文；
//  2. 不传 reproduction / 空壳 "{}"/只有 entry_point 无 steps → enricher 永不
//     触发（零回归红线：原版调用形态与本功能上线前逐字节一致）；
//  3. enricher 自身炸了（panic）不影响 finding 登记与工具返回。

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/evidence"
)

type captureEnricher struct {
	mu    sync.Mutex
	calls []reproCall
}

type reproCall struct {
	fid, tid int64
	repro    json.RawMessage
}

func (c *captureEnricher) fn(findingID, taskID int64, repro json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, reproCall{findingID, taskID, repro})
}

func (c *captureEnricher) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func (c *captureEnricher) waitFor(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.count() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("enricher called %d times, want >= %d within %v", c.count(), want, timeout)
}

func TestReportFindingReproEnricherDispatch(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return false }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })

	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("repro enrich dispatch", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	cap := &captureEnricher{}
	tsx := NewToolSet(nil, "")
	tsx.ts, tsx.taskID = d.Exploration(task.ExplorationID), task.ID
	tsx.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	tsx.SetReproEnricher(cap.fn)

	// (2) 零回归：不带 reproduction 的三种原版形态都不派发。
	for _, body := range []string{
		`{"vulnclass":"TEST","severity":"low","summary":"no repro"}`,
		`{"vulnclass":"TEST","severity":"low","summary":"empty repro","reproduction":{}}`,
		`{"vulnclass":"TEST","severity":"low","summary":"steps-less repro","reproduction":{"entry_point":"POST /a"}}`,
	} {
		res, err := tsx.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
			t.Fatalf("zero-regression report rejected: %v %s", err, res.Flatten())
		}
	}
	time.Sleep(50 * time.Millisecond) // 给错误的异步派发一点现形时间
	if n := cap.count(); n != 0 {
		t.Fatalf("enricher fired %d times on reproduction-less reports", n)
	}

	// (1) 带 steps → 落库后异步派发，参数正确。
	repro := `{"entry_point":"POST /upload","steps":[{"request":"POST /upload HTTP/1.1\nHost: x.com\n\n{\"f\":\"a.php\"}","response":"HTTP/1.1 200 OK","expected":"webshell","proves":"上传无校验"}]}`
	res, err := tsx.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"upload","severity":"high","summary":"with repro","reproduction":`+repro+`}`), nil)
	if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
		t.Fatalf("repro report rejected: %v %s", err, res.Flatten())
	}
	var out struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(res.Flatten(), "\n", 2)[1]), &out); err != nil {
		t.Fatal(err)
	}
	cap.waitFor(t, 1, 2*time.Second)
	cap.mu.Lock()
	defer cap.mu.Unlock()
	c := cap.calls[0]
	if c.fid != out.FindingID || c.tid != task.ID {
		t.Fatalf("enricher got (fid=%d,tid=%d), want (%d,%d)", c.fid, c.tid, out.FindingID, task.ID)
	}
	if !strings.Contains(string(c.repro), "POST /upload HTTP/1.1") {
		t.Fatalf("enricher lost the verbatim step text: %s", c.repro)
	}
	// 派发与否都不影响列初值：finding 的 reproduction 列必须已带完整原文。
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil || !json.Valid(f.Reproduction) || len(f.Reproduction) < 10 {
		t.Fatalf("reproduction column missing after report: %v", err)
	}
}

// TestReportFindingEnricherPanicIsolated：enricher 里 panic 不能拖垮 finding 登记。
func TestReportFindingEnricherPanicIsolated(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return false }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })

	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("repro enrich panic", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	// 模拟 host 侧炸裂的 enricher（server 实现自带 recover；这里测的是
	// handler 侧「派发即忘、不同步等待回调死活」的边界——登记与返回先于一切）。
	tsx := NewToolSet(nil, "")
	tsx.ts, tsx.taskID = d.Exploration(task.ExplorationID), task.ID
	tsx.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	tsx.SetReproEnricher(func(int64, int64, json.RawMessage) {
		defer func() { _ = recover() }()
		panic("traffic store exploded")
	})
	repro := `{"steps":[{"request":"GET /a HTTP/1.1\nHost: x.com","response":"HTTP/1.1 200"}]}`
	res, err := tsx.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"TEST","severity":"low","summary":"panic isolation","reproduction":`+repro+`}`), nil)
	if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
		t.Fatalf("finding lost to enricher panic: %v %s", err, res.Flatten())
	}
	time.Sleep(80 * time.Millisecond) // panic 若逃逸会在这一刻炸掉测试进程
}

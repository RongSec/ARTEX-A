package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestAdoptedReaderLinkExposesSourceGraph 验证「阅读者采纳 → 图暴露」：
// task_intel_links(decision=adopted) 一旦写入，被勾连任务就和不变量一样进入
// DirectSourceStores（graph_overview.related_tasks 与 inherited 读工具的共同来源），
// 而不仅仅是一条 hint。跨项目采纳不暴露整图。
func TestAdoptedReaderLinkExposesSourceGraph(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	proj, err := m.pg.CreateProject(db.CreateProjectInput{Name: "_reader_exposure_probe", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM projects WHERE id=$1`, proj.ID) })

	owner, err := m.CreateTaskWithOptions("owner", "owner goal", db.TaskCreateOptions{ProjectID: &proj.ID})
	if err != nil {
		t.Fatal(err)
	}
	source, err := m.CreateTaskWithOptions("source", "source goal", db.TaskCreateOptions{ProjectID: &proj.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.DeleteTask(owner.ID, DeleteTaskOptions{})
		_, _ = m.DeleteTask(source.ID, DeleteTaskOptions{})
	})

	ownerID := mustTaskID(t, owner.ID)
	sourceID := mustTaskID(t, source.ID)

	sources, err := owner.Store.DirectSourceStores()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 0 {
		t.Fatalf("没有静态关联时不该有来源，got %d", len(sources))
	}

	if _, err := m.pg.SaveTaskIntelLink(t.Context(), db.TaskIntelLink{
		ProjectID: proj.ID, TaskID: ownerID, RelatedTaskID: sourceID,
		Decision: "adopted", Reason: "同一接口 /api/user/{id}", DecidedBy: "reader",
	}); err != nil {
		t.Fatal(err)
	}

	sources, err = owner.Store.DirectSourceStores()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Task.TaskID != sourceID {
		t.Fatalf("adopt 后应把被勾连任务暴露为来源，got %+v", sources)
	}
	if sources[0].Store == nil || sources[0].Task.ExplorationID != source.ExpID {
		t.Fatal("被勾连任务应绑定到自己的探索图 store（继承读路径靠它）")
	}

	// 跨项目：换到另一个项目后，该采纳不应再暴露整图。
	other, err := m.pg.CreateProject(db.CreateProjectInput{Name: "_reader_exposure_other", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM projects WHERE id=$1`, other.ID) })
	if _, err := m.pg.Exec(`UPDATE tasks SET project_id=$1 WHERE id=$2`, other.ID, sourceID); err != nil {
		t.Fatal(err)
	}
	sources, err = owner.Store.DirectSourceStores()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 0 {
		t.Fatalf("跨项目采纳不应暴露整图，got %d", len(sources))
	}
}

package db

// V6-DUAL：projects 两个尺度开关各自独立——observer_enabled（跨任务/项目内）
// 与 reader_enabled（跨项目）在 Create/Update 里各写各的列，绝不被镜像成
// 同值（撤销 V6-U4 的数据层镜像）。PG 集成测：无库自动 skip（照 testDSN 范式）。

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestProjectSwitchesIndependent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := strconv.FormatInt(time.Now().UnixNano()%1000000, 10)

	// Create 只给 observer：reader 必须保持默认关（不镜像）。
	onlyObserver, err := d.CreateProject(CreateProjectInput{
		Name: fmt.Sprintf("dual-observer-%s", suffix), ObserverEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM projects WHERE id=$1`, onlyObserver.ID) //nolint:errcheck
	if !onlyObserver.ObserverEnabled || onlyObserver.ReaderEnabled {
		t.Fatalf("只传 observer_enabled 不应镜像 reader_enabled: %+v", onlyObserver)
	}

	// Create 只给 reader：observer 必须保持默认关。
	onlyReader, err := d.CreateProject(CreateProjectInput{
		Name: fmt.Sprintf("dual-reader-%s", suffix), ReaderEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM projects WHERE id=$1`, onlyReader.ID) //nolint:errcheck
	if onlyReader.ObserverEnabled || !onlyReader.ReaderEnabled {
		t.Fatalf("只传 reader_enabled 不应镜像 observer_enabled: %+v", onlyReader)
	}

	// Update 只给 observer：reader 现值不动。
	off, on := false, true
	got, err := d.UpdateProject(onlyReader.ID, UpdateProjectPatch{ObserverEnabled: &on})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ObserverEnabled || !got.ReaderEnabled {
		t.Fatalf("只改 observer 不该动 reader: %+v", got)
	}
	got, err = d.UpdateProject(onlyReader.ID, UpdateProjectPatch{ObserverEnabled: &off})
	if err != nil {
		t.Fatal(err)
	}
	if got.ObserverEnabled || !got.ReaderEnabled {
		t.Fatalf("只关 observer 不该关 reader: %+v", got)
	}

	// Update 只给 reader：observer 现值不动。
	got, err = d.UpdateProject(onlyObserver.ID, UpdateProjectPatch{ReaderEnabled: &on})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ObserverEnabled || !got.ReaderEnabled {
		t.Fatalf("只改 reader 不该动 observer: %+v", got)
	}
	got, err = d.UpdateProject(onlyObserver.ID, UpdateProjectPatch{ReaderEnabled: &off})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ObserverEnabled || got.ReaderEnabled {
		t.Fatalf("只关 reader 不该关 observer: %+v", got)
	}
}

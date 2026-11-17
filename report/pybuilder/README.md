# pybuilder（docx 渲染脚本）

两条渲染链：

- `report_builder.py`：从零 `Document()` 按章节重建（无模板原件的回退路径）。
- `template_filler.py`：以用户上传的模板原件为底稿只改内容（保留页眉页脚/
  封面/表格框线/多级标题样式）。Go 侧 `ReportInput.TemplateDocx` 非空时使用。

## 测试

Python 断言套件（需要 python3 + python-docx）：

```bash
cd report/pybuilder
python -m unittest test_report_builder -v      # 旧重建渲染规范
python -m unittest test_template_filler -v     # 模板填充（样本 tpl_cn.docx）
```

Go 侧入口（`go test ./report/`）：

- `TestPyBuilderSpecSuite` → `test_report_builder`
- `TestTemplateFillerSpecSuite` → `test_template_filler`
- `TestGenerateDocxMissingTemplateFallsBack` → 模板缺失回退旧重建链

无 python / 无 python-docx 环境以上 Go 测自动 skip。

# Examples

`demo-project/` 是一个虚构的 Node.js/Express 博客 API 的**完整审计产物样例**（仓库里只有 `.sast/` 输出，没有源代码——文件中引用的 `src/...` 路径是虚构的）。

它演示了完整的数据契约：

| 文件 | 看点 |
| --- | --- |
| `VULN_LCSR_1.json` | 结构化项目画像：入口点带 `auth_required`，信任边界显式写出 enforcement |
| `VULN_LCSR_2.json` | 自由探索产物：SQL 注入（后确认）与 SSRF（后被认定误报），全部 `pending_review` |
| `VULN_LCSR_3.json` | 清单补漏产物：新发现 IDOR + 10 类 `checklist_coverage` 逐类结论 |
| `VULN_LCSR_4.json` | 复查产物：`confirmed` / `updated` / `false_positive` 三种终态、名称前缀标记与 `review_note` |
| `results.json` | 权威汇总：按严重性排序的确认漏洞 + `false_positives` 复盘区 + summary 计数 |

运行校验器验证本样例：

```bash
pip install "jsonschema>=4.18"
python3 sast-code-audit/scripts/validate.py --root examples/demo-project
```

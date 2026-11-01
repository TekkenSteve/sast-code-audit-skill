# 模块三检查清单（10 类）

定位：**补漏**。逐类检查并输出 `checklist_coverage`（`vulnerable / clean / not_applicable` + 简短理由）。
模块二已发现的问题交叉引用其 id，不重复立项；新增发现前先按指纹比对模块二产物。

## 受控词表（vuln_type）

优先使用以下取值（不适用时允许自定 snake_case，但需在 `risk_description` 说明）：

```
sql_injection, nosql_injection, command_injection, code_injection, template_injection,
expression_injection, log_injection, xpath_injection, ldap_injection,
path_traversal, arbitrary_file_read, arbitrary_file_write, arbitrary_file_delete,
file_upload, file_inclusion,
ssrf, xxe, open_redirect, insecure_url_fetch,
auth_bypass, session_fixation, jwt_flaw, oauth_flaw, password_reset_flaw,
idor, horizontal_authz, vertical_authz, tenant_isolation, privilege_escalation,
insecure_deserialization, business_logic,
sensitive_data_exposure, debug_interface_exposure, admin_interface_exposure, error_info_leak,
stored_xss, dom_xss, server_xss, dependency_chain
```

---

## 1. injection
- **检查要点**：SQL/NoSQL/LDAP/XPath 查询拼接；shell 命令拼接；eval/script 注入；模板与表达式引擎（freemarker、velocity、jinja2、EL、SpEL）；日志 CRLF。
- **典型 source**：`req.query/body/params`、header、读库的二阶数据。
- **典型 sink**：`db.raw` / `orderByRaw`、字符串拼 SQL、`child_process.exec`、`eval`、模板引擎 `render_string`。
- **误报排除**：绑定变量、白名单映射列名、ORM 构造器自动转义（raw 除外）。
- **CWE**：CWE-89 / 78 / 94 / 1336。

## 2. files-paths
- **检查要点**：用户输入进入路径拼接；任意读/写/删除；上传的落盘名、类型校验、解析链（`.php` 双扩展、zip slip）；本地/远程文件包含。
- **典型 sink**：`readFile(join(dir, name))`、`fs.unlink`、`move_uploaded_file`、`extractall`。
- **误报排除**：`realpath` 后前缀校验；上传名重命名为服务端随机名 + 扩展白名单。
- **CWE**：CWE-22 / 434 / 98。

## 3. request-network
- **检查要点**：服务端按用户指定 URL 发起请求（SSRF）；XML 外部实体；开放重定向；不安全协议拉取。
- **典型 sink**：`axios.get(userUrl)`、`urlopen`、`HttpClient`；XML 解析器默认实体开启。
- **误报排除**：出网前的 scheme+域名白名单封装且该封装确被调用路径覆盖；解析器显式禁用外部实体。
- **CWE**：CWE-918 / 611 / 601。

## 4. auth-session
- **检查要点**：认证绕过（路由遗漏中间件、HTTP 方法差异、大小写/尾斜杠绕过）；会话固定；JWT 算法混淆 / 未验签 / 弱密钥 / 不校验 exp；OAuth 回调 state 与 redirect_uri 校验；密码重置令牌可预测、可重放、无时效。
- **误报排除**：框架级统一鉴权且路由确已覆盖；令牌为高熵随机 + 一次性 + 时效。
- **CWE**：CWE-287 / 384 / 347 / 613。

## 5. authorization
- **检查要点**：IDOR（对象标识用户可控且无归属校验）；水平/垂直越权；租户隔离缺失；角色边界绕过；批量接口逐 id 鉴权缺失。
- **方法**：按 `references/methodology.md` §5 四步核对。
- **误报排除**：资源归属在 repository 层统一过滤（如 query 自动带 `tenant_id`）。
- **CWE**：CWE-639 / 862 / 863。

## 6. deserialization
- **检查要点**：Java（ObjectInputStream、Fastjson/Jackson default typing、XStream）；PHP `unserialize`；Python `pickle`/`yaml.load`；Node `node-serialize`。重点看数据是否跨过信任边界。
- **误报排除**：输入完全由服务端生成且签名保护；仅反序列化基本类型；gadget 链不存在且不可控。
- **CWE**：CWE-502。

## 7. business-logic
- **检查要点**：支付金额/数量客户端可控；审批流状态机跳步；邀请码/兑换码可暴力或重放；竞态（余额检查与扣减非原子）；权限提升链（普通接口可改角色字段）。
- **误报排除**：关键不变量在服务端强制（金额服务端计算、状态机转换表校验、幂等锁）。
- **CWE**：CWE-840 / 367 / 269。

## 8. data-exposure
- **检查要点**：API 返回体含越权字段（密码哈希、内部 id、他人 PII）；debug/actuator/swagger 暴露；管理接口无鉴权直挂公网；错误页/堆栈泄露敏感配置。
- **误报排除**：调试端点有独立强认证且非公网；响应序列化器已显式白名单字段。
- **CWE**：CWE-200 / 215 / 540。

## 9. client-side
- **检查要点**：存储型 XSS（入库未净化、出库按 HTML 渲染）；DOM XSS（`innerHTML`、`document.write`、`eval` 消费 location/referrer）；服务端模板注入导致的 XSS。
- **误报排除**：输出按上下文编码；富文本经白名单净化器（如 DOMPurify）且配置正确。
- **CWE**：CWE-79。

## 10. dependencies-config
- **检查要点**：**仅当能形成实际利用链**才报告：已知 RCE/认证绕过 CVE 且调用路径可达该缺陷功能；危险默认配置（调试模式开、Actuator 全开）；不安全的权限模型（对象存储公开可写）。
- **误报排除**：CVE 存在但项目未调用受影响代码路径；仅理论上的漏洞类 CVE；DoS/信息泄露类 CVE（属排除项）。
- **CWE**：CWE-1104。

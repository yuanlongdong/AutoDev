# AI Vulnerability Researcher

授权安全研究版自动化源码漏洞研究引擎。从"扫描器"升级为"漏洞研究员"。

## 当前能力（v0.2.0）

### 程序分析
- Python AST 提取（函数/类/调用/控制流/异常/import）
- 轻量 CFG 构建（基本块 + 分支/循环/异常边）
- 跨函数调用图 + 可达性分析
- 函数内数据流（def-use 链）
- 污点传播分析（SOURCE→TRANSFORM→SANITIZER→SINK，函数内 + 跨函数）

### 漏洞检测（16 个结构化检测器 + 7 条正则 fallback）
- SQL Injection（区分 ORM 参数化与 raw 拼接）
- Command Injection、NoSQL Injection
- Path Traversal、Arbitrary File Read/Write
- SSRF、Open Redirect
- XSS、SSTI
- Dangerous Deserialization（pickle/yaml.unsafe）
- File Upload（无 secure_filename/扩展名检查）
- Hardcoded Secret、Weak Cryptography（MD5/SHA1/DES/ECB）
- Insecure Defaults（debug=True/host=0.0.0.0）
- Authentication Bypass、IDOR

### 研究闭环
- E0–E5 证据等级自动评估与升级
- 反证机制（隐藏 Sanitizer/中间件鉴权/ORM 自动参数化/框架自动编码）
- 9 条自动降级规则
- 根因分析（8 类系统性缺陷）
- 变体分析（五维搜索 + 漏洞家族聚类）
- 漏洞链分析（7 条链规则）
- 16 项质量门槛检查
- 自动研究循环编排器（12 步，变体迭代 max 3 轮）

### 输出
- 15 章节 Markdown 报告
- SARIF 2.1.0
- JSON
- 攻击面报告（10 类资产）
- 项目 IR（JSON）

## 使用

```bash
# 基础扫描
python -m vulnresearch.cli /path/to/source --json findings.json

# 完整报告
python -m vulnresearch.cli /path/to/source --report report.md

# 同时输出多种格式
python -m vulnresearch.cli /path/to/source --json out.json --sarif out.sarif --report report.md

# 攻击面
python -m vulnresearch.cli /path/to/source --attack-surface

# 项目 IR
python -m vulnresearch.cli /path/to/source --ir
```

## 研究原则

- 只对用户明确有权审计的源码工作
- 静态分析，不执行目标代码，不发起网络请求
- 缺失信息显式标记 UNKNOWN，不脑补
- 准确性 > 数量；证据 > 猜测；根因 > 表象
- 发现 ≠ 漏洞，漏洞 ≠ 可利用，可利用 ≠ 已验证

## 测试

```bash
python -m pytest tests/ -v   # 170 passed
```

## 依赖

纯 Python 标准库，无第三方依赖。Python >= 3.9。

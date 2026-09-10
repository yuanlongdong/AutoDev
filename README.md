# AutoDev

## AI Vulnerability Researcher v0.2.0

AutoDev 包含一个授权范围内的自动化源码漏洞研究引擎：`vulnresearch/`。

它按照 **"目标建模 → 代码资产分析 → 程序结构建模 → Source/Sink 定位 → 污点分析 → 认证授权分析 → 证据评级 → 根因分析 → 变体挖掘 → 漏洞链 → 质量门槛 → 报告"** 的完整研究闭环工作，从启发式扫描器升级为真正的漏洞研究员。

### 核心能力

- **统一漏洞对象**：20+ 字段的 `Vulnerability`（PHASE 26），覆盖 Source→Data Flow→Sanitizer→Auth→Authz→Reachability→Sink→Impact 完整证据链
- **程序分析**：Python AST → CFG → Call Graph → Data Flow → Taint Analysis（PHASE 2）
- **58 种漏洞类别**：Web/API(13) + Authentication(8) + Authorization(7) + Business Logic(9) + Native/Memory(14) + Supply Chain(7)（PHASE 5）
- **16 个结构化检测器**：SQL注入（区分ORM）、命令注入、路径穿越、SSRF、XSS、SSTI、硬编码密钥、危险反序列化、任意文件写、文件上传、开放重定向、弱加密、不安全默认值、认证绕过、IDOR、NoSQL注入
- **E0–E5 证据等级**：自动升级/降级，从 E1（可疑代码）升级到 E2（Source→Sink）甚至 E3（可达+边界失效）（PHASE 14）
- **反证机制**：主动寻找隐藏 Sanitizer、中间件鉴权、ORM 自动参数化、框架自动编码（PHASE 21）
- **自动降级**：9 条降级规则（Unknown Sanitizer/Authz/Reachability、Dead Code、Test-only 等）（PHASE 19）
- **根因分析**：从漏洞点归纳系统性缺陷，8 类根因（PHASE 9）
- **变体分析**：五维搜索同类漏洞，按根因聚类为漏洞家族（PHASE 8）
- **漏洞链分析**：7 条链规则，多个低危问题组合为高影响链（PHASE 10）
- **质量门槛**：16 项检查清单，不通过不得标记 Confirmed（PHASE 28）
- **自动研究循环**：12 步编排器，变体迭代直到无新高价值发现（PHASE 24）
- **15 章节报告**：Markdown 报告（PHASE 27）+ SARIF 2.1.0 + JSON
- **攻击面分析**：识别 10 类资产（HTTP Handler/RPC/CLI/WebSocket/Queue/Cron/File Parser/Upload/Admin API/Internal API）（PHASE 1）
- **认证授权深度分析**：Authentication→Identity→Role→Permission→Object Ownership→Tenant→Action 链路（PHASE 6）
- **业务逻辑状态机**：识别非法状态转换、顺序绕过、非幂等操作（PHASE 7）

### 安装与使用

```bash
# 无需第三方依赖，Python >= 3.9
cd AutoDev
pip install -e .

# 基础扫描（向后兼容）
vulnresearch /path/to/authorized/source --json findings.json --sarif findings.sarif

# 完整研究报告
vulnresearch /path/to/authorized/source --report report.md

# 输出项目 IR（JSON）
vulnresearch /path/to/authorized/source --ir

# 攻击面报告
vulnresearch /path/to/authorized/source --attack-surface

# 详细输出
vulnresearch /path/to/authorized/source --verbose

# 不安装直接运行
python -m vulnresearch.cli /path/to/authorized/source --json findings.json --report report.md
```

### 测试

```bash
python -m pytest tests/ -v
# 170 passed
```

### 安全边界

本工具用于用户明确有权审计的源码、内部测试环境、开源项目、CTF 和本地沙箱。

- ✅ 静态分析，不执行目标代码
- ✅ 不发起网络请求
- ✅ 非破坏性验证，默认不执行攻击载荷
- ✅ 缺失信息显式标记 UNKNOWN，不脑补
- ❌ 不用于未授权系统、第三方生产环境
- ❌ 不窃取凭据、不建立持久化、不进行破坏性操作

### 项目结构

```
vulnresearch/
├── models.py            # 统一漏洞对象 (PHASE 26)
├── knowledge_base.py    # Source/Sink/类别知识库 (PHASE 3/4/5)
├── ir.py                # AST 提取 (PHASE 2)
├── cfg.py               # 控制流图 (PHASE 2)
├── callgraph.py         # 调用图 (PHASE 2)
├── dataflow.py          # 数据流 (PHASE 2)
├── taint_engine.py      # 污点分析 (PHASE 2)
├── evidence_engine.py   # E0-E5 证据评级 (PHASE 14)
├── severity.py          # 严重性评级 (PHASE 23)
├── downgrade.py         # 自动降级 (PHASE 19)
├── counter_evidence.py  # 反证机制 (PHASE 21)
├── project_model.py     # 目标建模 (PHASE 0)
├── asset_analyzer.py    # 代码资产分析 (PHASE 1)
├── auth_analyzer.py     # 认证授权分析 (PHASE 6)
├── detectors.py         # 检测器 (PHASE 5)
├── state_machine.py     # 业务状态机 (PHASE 7)
├── root_cause.py        # 根因分析 (PHASE 9)
├── variant_analyzer.py  # 变体分析 (PHASE 8)
├── chain_analyzer.py    # 漏洞链分析 (PHASE 10)
├── quality_gate.py      # 质量门槛 (PHASE 28)
├── orchestrator.py      # 研究循环编排 (PHASE 24)
├── report.py            # Markdown 报告 (PHASE 27)
├── verifier.py          # 安全验证 (PHASE 13)
├── engine.py            # 整合引擎
├── cli.py               # 命令行入口
└── ast_engine.py        # AST 引擎入口
```

详细开发状态请参阅 [docs/DEVELOPMENT_SUMMARY.md](docs/DEVELOPMENT_SUMMARY.md)。

## AutoDev 原有目标

- GitHub 项目分析
- 代码生成与修改
- 自动测试
- CI/CD
- Issue / PR 管理
- 项目文档和开发日志

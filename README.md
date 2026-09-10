# AutoDev

## AI Vulnerability Researcher

AutoDev 现在包含一个授权范围内的自动化源码漏洞研究引擎：`vulnresearch/`。

它按照“Source → Data Flow → Sink → Evidence → Root Cause → Variant”的研究模型工作，目标是逐步从启发式扫描升级为真正的程序分析与漏洞研究平台。

### 当前 MVP

- 多语言源码遍历
- Source / Sink 启发式检测
- SQL Injection
- Command Injection
- Path Traversal
- SSRF
- Dangerous Deserialization
- Potential XSS
- Hardcoded Secret
- E1 候选证据输出
- Finding JSON
- 基于位置和代码片段去重
- Python CLI
- 回归测试

### 使用

```bash
python -m vulnresearch.cli /path/to/authorized/source --json findings.json
```

或安装后：

```bash
vulnresearch /path/to/authorized/source --json findings.json
```

### 演进路线

```text
MVP 启发式检测
    ↓
AST
    ↓
CFG + Call Graph
    ↓
跨函数 Data Flow / Taint
    ↓
认证与授权模型
    ↓
Root Cause
    ↓
Variant Analysis
    ↓
本地 Sandbox 验证
    ↓
Fuzzing + Crash Triage
    ↓
漏洞家族聚类
    ↓
SARIF / SRC 报告
```

### 安全边界

本工具用于用户明确有权审计的源码、内部测试环境、开源项目、CTF 和本地沙箱。默认不执行攻击载荷、不连接未知外部目标、不处理真实第三方凭据、不进行破坏性验证。

## AutoDev 原有目标

- GitHub 项目分析
- 代码生成与修改
- 自动测试
- CI/CD
- Issue / PR 管理
- 项目文档和开发日志

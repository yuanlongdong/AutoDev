# AI Vulnerability Researcher

授权安全研究版自动化源码漏洞挖掘器。

## 当前能力

- 多语言源码遍历
- Source / Sink 启发式检测
- SQL Injection / Command Injection / Path Traversal / SSRF
- Dangerous Deserialization / XSS / Hardcoded Secret
- E0-E5 证据体系的 E1 自动初筛
- Finding JSON 输出
- 基于路径/位置/代码片段的去重
- 默认排除构建目录、依赖目录和 Git 元数据

## 使用

```bash
python -m vulnresearch.cli /path/to/authorized/source --json findings.json
```

## 研究原则

工具只对用户明确有权审计的源码、测试环境、开源项目、CTF 和本地沙箱工作。初版检测器只产生候选证据，不执行攻击载荷，也不访问外部目标。

## 后续路线

1. AST / CFG / Call Graph
2. 跨函数数据流与 Taint Analysis
3. 认证/授权模型
4. Root Cause 与 Variant Analysis
5. 本地 Docker 沙箱验证
6. Fuzzing / crash triage
7. 漏洞家族聚类
8. 回归测试与 SARIF 报告

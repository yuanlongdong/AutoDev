# 《人生如戏》P0 Codex 开发接管说明

## 目标
把《人生如戏》GDD v1.0 的 P0 Demo 落地为可运行原型。不要继续扩展策划案，优先完成可玩的核心闭环。

## P0 范围
- 1 个剧本：职场新人（18–25）
- 36 个月生命周期
- 月度现金流结算
- 职业与理财技能
- 6 个核心技能节点
- 10 个基础人生事件
- 简单结局判定
- 本地存档/读档
- 基础 UI

## 核心循环
每个月严格执行：
1. 进入月度状态
2. 结算收入/固定支出/生活支出
3. 生成可触发事件
4. 玩家做选择
5. 应用选择结果
6. 更新属性、技能、现金流和月份
7. 记录月度复盘数据
8. 进入下一月

## 技术原则
- Unity + C#
- 数据与逻辑分离
- 剧本、事件、技能、职业等内容数据化
- 优先使用 ScriptableObject 或 JSON；不要把游戏数值硬编码在 UI 中
- UI 只负责展示和输入，不负责核心规则
- 核心系统可单元测试
- 不接后端、不做联网、不做账号系统，P0 全部本地运行

## 推荐结构
Assets/Scripts/
  Core/
  Gameplay/
  Economy/
  Skills/
  Events/
  Story/
  Save/
  UI/
  Tests/

## 最低数据模型
GameState
- age
- month
- cash
- income
- fixedExpenses
- livingExpenses
- attributes
- skills
- currentCareer
- eventHistory
- endingState

Skill
- id
- name
- category
- level
- maxLevel
- description

LifeEvent
- id
- title
- description
- conditions
- choices
- effects

Choice
- id
- text
- effects

Effect
- cashDelta
- incomeDelta
- attributeDelta
- skillDelta
- flags

## P0 验收标准
- 新游戏可以开始
- 月份可以从 1 推进到 36
- 每月现金流计算结果正确且可观察
- 事件能根据条件出现
- 玩家选择后状态发生正确变化
- 技能升级可用
- 36 个月结束后能得到结局
- 关闭游戏后重新打开可以继续进度
- 核心规则有自动化测试
- 项目能在干净环境中打开并运行

## 开发顺序
### Phase 1 — 工程骨架
建立 Unity 项目结构、程序集/命名空间、基础 GameState、GameManager、事件总线和测试框架。

### Phase 2 — 月度循环
实现 MonthLoop：开始月份 → 结算 → 事件 → 选择 → 应用结果 → 月份+1。

### Phase 3 — 经济系统
实现收入、固定支出、生活支出、现金余额及破产/现金不足状态。

### Phase 4 — 技能系统
实现技能数据、等级、升级条件和技能效果。P0 只实现职业与理财相关技能。

### Phase 5 — 事件系统
实现 10 个事件及条件/选择/效果。事件内容以 GDD 为准，不自行大幅扩写。

### Phase 6 — UI
实现主界面、现金流、技能、事件选择、月份进度、结局界面。

### Phase 7 — 存档
实现至少 3 个本地存档槽或一个自动存档；保证版本字段可扩展。

### Phase 8 — 测试与 Demo
跑完整 36 个月流程；修复阻塞问题；补核心系统测试；形成可交付 Demo。

## Codex 工作方式
- 先检查仓库现状，再开始修改。
- 每个 Phase 独立提交。
- 不要一次性生成大量无验证代码。
- 每完成一个 Phase：运行测试/构建，修复问题，再提交。
- 提交信息使用：`feat: ...` / `fix: ...` / `test: ...`。
- 不要为了 P0 引入不必要的第三方依赖。
- 遇到 GDD 未定义的细节，选择最小可行实现，并在 `docs/DECISIONS.md` 记录，不要阻塞开发。
- P0 完成前禁止扩展四幕完整人生、联网、排行榜、社交、AI 等非 P0 功能。

## 当前任务
从 Phase 1 开始，直接实施，不要只写方案。
完成后继续 Phase 2，依次推进到 P0 Demo 完成。

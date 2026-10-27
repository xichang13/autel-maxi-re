# 技能观察日志

记录任务中的可复用方法与技能改进候选。状态：OPEN＝待处理；ACTIONED＝已应用；DECLINED＝已决定不处理。

首次建立：2026-10-23。本次仅初始化记录；没有执行技能周审、修改技能、修改 AGENTS.md 或注册自动化。

---

## 2026-10-23

### Observation 001: 进程外取样与二进制传输隔离

**Status:** OPEN
**Date:** 2026-10-23
**Session context:** Android 应用运行时 DEX 取样。
**Skill:** 新技能候选：Android DEX 内存取样
**Type:** open-source
**Phase/Area:** 取样故障分析、二进制落盘与验证

**Issue:** 一次进程内注入尝试后，目标进程出现 SIGSEGV，脚本失效，未取得 DEX。随后在具备 root 读取权限的环境中，进程外读取内存取得了 DEX 样本。root 命令的 stdout 还包含 daemon 诊断文本，直接将其作为二进制流会污染输出。仅凭时间先后无法确认崩溃由反注入机制导致；已取回样本仍需结构审计。

**Suggested improvement:** 候选技能应先记录目标版本、进程与失败证据；在权限具备时，将进程外取样作为可验证的替代路径。二进制先写入设备独立文件，再通过文件传输取回，并验证长度、DEX 头部、节区范围、校验值与解析结果。对崩溃原因和完整性分别标注已证实事实与待验证推断。

**Principle:** 取样路径与数据传输路径应分别验证；诊断输出与二进制载荷必须隔离。替代路径成功只能证明取得数据，不能单独证明故障原因或数据完整性。

**Reference file:** `D:\DirFile\2610\autel\dex_dump\com.autel.update_20261023_134829\journal.md`

### Observation 002: 截断 DEX 前审计尾部方法体与驻留覆盖

**Status:** OPEN
**Date:** 2026-10-23
**Session context:** 对多个进程的 DEX 内存快照进行结构审计与方法体恢复。
**Skill:** 新技能候选：Android DEX 内存取样
**Type:** open-source
**Phase/Area:** 有效范围裁剪、运行时方法恢复与验收

**Issue:** 多个快照的正式 DEX 区域相同，但尾部包含不同的已驻留 code_item。正式区域中的一批方法仍为 NOP/default return 桩；清除保护标记或修正头部校验值不会恢复实际逻辑。原始样本能以成功退出状态被反汇编，也不能说明语义完整。比较尾部并验证匹配后，才确认可恢复的方法并集及仍未恢复的保护桩数量。

**Suggested improvement:** 在截取正式 DEX 有效区之前，保留原始映射并检查尾部是否保存运行时恢复的 code_item。跨快照合并时验证方法映射唯一性、原槽长度、try/handler 匹配和重复项内容一致性，并记录方法来源及明确的驻留覆盖。验收应分别检查结构/校验值、反汇编以及实际方法体证据，明确列出残留保护桩。

**Principle:** 文件边界与可解析性不足以证明语义完整。恢复完整性需要方法体证据及可核对的驻留覆盖；裁剪不能先于尾部审计。

**Reference file:** `D:\DirFile\2610\autel\dex_dump\com.autel.update_20261023_134829\journal.md`

### Observation 003: 完整方法池与多来源字节证据

**Status:** OPEN
**Date:** 2026-10-23
**Session context:** 从部分驻留方法恢复扩展到完整保护代码池还原。
**Skill:** 新技能候选：Android DEX 内存取样
**Type:** open-source
**Phase/Area:** 完整载荷定位、静态算法适配和语义验收

**Issue:** 内存中的已驻留代码只覆盖部分方法。原始包中仍保存完整代码池；公开研究的固定定位签名在当前版本失效，但资源派生规则经本地验证适用。普通反编译器的控制流重构失败不能单独用作代码缺失证据。

**Suggested improvement:** 完整恢复应检查原始包中的代码池，分别验证密钥派生和完整置换表；用多个架构资源与运行时内存互证，用全部已知真实方法逐字节验证，再对全方法池建立一一映射。保留正常源码与指令式视图并分别报告工具限制。

**Principle:** 完整性来自载荷覆盖、一一映射和独立字节证据；版本适配必须验证具体样本，反编译器输出不能替代字节码验收。

**Reference file:** `D:\DirFile\2610\autel\dex_dump\com.autel.update_full_20261023_142233\README.md`
### Observation 4: 比较 DEX 先确认版本与全零空洞

**Status:** OPEN
**Date:** 2026-10-23
**Session context:** 比较两个来源不明的 Android DEX。
**Skill:** 新技能候选：Android DEX 内存取样
**Type:** open-source
**Phase/Area:** 版本鉴别与文件布局比较

**Issue:** 较大的 DEX 可能包含更少的类和方法，因为标准节之间保留了大块全零区域。仅凭文件名或体积会误判代码覆盖；实际执行的版本常量提供了不同构建的直接证据。

**Suggested improvement:** 比较时先核验版本常量与类/方法集合，再依照 map 和真实 item 边界计算空洞，最后按完整签名和归一化引用比较方法。把裸 DEX 可证事实与其 APK 来源推断分开报告。

**Principle:** DEX 体积与代码内容量没有单调关系；版本和布局都可能显著改变文件长度。

**Reference file:** `D:\DirFile\2610\autel\dex_dump\com.autel.update_full_20261023_142233\compare_11698912\comparison_summary.json`

### Observation 005: 脱壳工具必须区分采集、结构与完整恢复

**Status:** OPEN
**Date:** 2026-10-23
**Session context:** 将一次 Android DEX 完整恢复整理成可手工复现的脚本包。
**Skill:** 新技能候选：Android DEX 内存取样
**Type:** open-source
**Phase/Area:** 工具打包、验证范围和失败处理

**Issue:** 单一成功信号容易被误用：内存文件有 DEX 魔数只证明采集到了候选；校验和和反汇编通过只证明结构可读；恢复报告字段一致也不是独立的语义审计。工具测试还发现 root 文件权限、SDK 退出码为零但日志有错误，以及输出路径碰撞等容易遗漏的失败模式。

**Suggested improvement:** 可复用流程应拆成采集、离线恢复、严格验证三个独立阶段。每阶段输出 manifest、原始日志和哈希；完整恢复必须要求代码池一一映射、残留项为零，并明确独立语义审计是否执行。脚本必须拒绝覆盖输入，二进制通过设备文件传输，并扫描工具完整诊断而非只看退出码。

**Principle:** 恢复结论的强度不得超过实际证据范围；可复现工具应把证据边界和失败条件编码进输出格式与测试。

**Reference file:** `D:\DirFile\2610\autel\manual_dex_unpack\README.md`

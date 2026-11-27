# batch51-py-safety-c-38

## 题面

符号执行平台这周三次卡住。第一次，某个解析函数的分叉数远超预期，队列里堆着几千个状态没人处理，跑完报告写无可达缺陷，实际上大半状态根本没探索；第二次，求解器碰到一条超时约束直接返回不可达，把整条分支判死，事后发现该分支里就藏着越界写；第三次，合并点上有分支还挂着没有求解的约束，工具却标成已证明安全，评审据此签了字。范围是 gsb/batch51-py-safety-c-38/symexec_state_budget_guard.py，类 SymExecBudgetGuard，负责管理状态队列、分叉预算与求解超时。

公开接口：SymExecBudgetGuard(*, max_states=64, max_forks_per_function=4, max_solves_per_function=8, max_constraints=8, max_iterations=3, solver=None)；enqueue(function, constraints=(), *, deadline_ms=0)；state(state_id)；states()；fork_state(state_id, condition, *, loop=False)；merge_states(state_ids)；solve(state_id)；expire(now_ms)；report()；snapshot()；restore(state)；模块级 negate_condition(condition)。异常统一 SymExecError(code, detail)。

要修的行为：①约束串是左、运算符、右三个空白分隔的词，运算符限 ==、!=、<、<=、>、>=，左右为整数或标识符，不合法报 SYMEXEC_CONSTRAINT_INVALID，单条超过 64 字符报 SYMEXEC_CONSTRAINT_TOO_LONG，折叠后条数超过 max_constraints 报 SYMEXEC_CONSTRAINT_LIMIT；②变量按首次出现顺序改名成 v0、v1，两侧都是整数时折叠，恒真丢弃，恒假把状态置 infeasible 且 reachable 为假，除改名与折叠外不做其它等价化简；③全部状态数硬顶 max_states，超限报 SYMEXEC_STATE_LIMIT，已有状态不受影响；④fork_state 产出 taken 与 skipped 两个子状态，条件取反为 == 换 !=、< 换 >=、<= 换 >，反向同理，子状态约束是父约束加条件后整体重新归一；⑤每次分叉消耗一次函数级配额，配额耗尽后照样建子状态但标 unexplored，Fork 的 exhausted 为真、remaining 为 0，不得静默丢弃；⑥loop=True 时子状态 iterations 加一，超过 max_iterations 标 unexplored 且不消耗分叉配额；⑦求解器由构造参数注入，返回 sat 或 unsat，状态置 solved，unsat 同时把 reachable 置假；⑧求解器抛 TimeoutError 时结果为 unknown，状态保持 queued 与可达、不写缓存、单列计数；同一状态再次求解命中缓存，cached 为真且不再消耗配额；⑨每函数求解次数另有上限，超限报 SYMEXEC_SOLVE_BUDGET_EXHAUSTED 且状态保持 queued；⑩merge_states 要求同函数，约束按传入顺序取并集去重，合并结果状态为 merged，任一分支还没求解时 proven_safe 必须为假，全部分支都求解过才为真，函数不同报 SYMEXEC_MERGE_MISMATCH；⑪expire(now_ms) 把 deadline_ms 小于等于 now 的 queued 状态标 expired 并返回条数，deadline_ms 为 0 表示不过期，已过期状态求解报 SYMEXEC_STATE_EXPIRED，未知 id 报 SYMEXEC_STATE_UNKNOWN；⑫report 返回 total_states、queued、solved、unexplored、merged、expired、infeasible、forks、cache_hits、timeouts 与 budget，budget 按函数名排序给出 forks_remaining 与 solves_remaining；快照以 state_id 字符串为键保存 states 与 budget，必须深拷贝，非法结构报 SYMEXEC_SNAPSHOT_INVALID 且原状态一字不改。状态 id 自 1 起单调递增，states() 按 id 升序返回元组。

硬约束：状态队列由锁保护，多线程并发入队与求解时 state_id 不得重复、计数不得丢；快照恢复后队列、预算与已探索边可往返。

State 含 state_id、function、constraints、status、reachable、iterations、deadline_ms、proven_safe，Fork 含 parent_id、taken_id、skipped_id、remaining、exhausted，SolverResult 含 state_id、status、cached。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。交付改好的源码与自测输出，说明每处改动的触发条件。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: symexec_state_budget_guard
- typeName: SymExecBudgetGuard

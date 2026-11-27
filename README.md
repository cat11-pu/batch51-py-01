# batch51-py-safety-a-09

## 题面

注销合规这季度被抽查出三处问题：三个存储分片里有两个回了删除成功，冷备里还能查到该主体的记录；同一个人注销后马上重新注册，旧请求的迟到回执把新账号资料删了；有个分片连续无响应，台账却显示全部完成。分片主要是对象存储、检索索引与审计库，任何一片没有回执都算未完成；注销请求可能因为用户反悔或重新注册而出现多个 generation，回执必须带回 generation 才能落到正确那一份上。合规要求每一份删除都能追到分片、回执与复核结果，未闭合的残留必须显式挂出来。范围是 gsb/batch51-py-safety-a-09 的 subject_erasure_ledger.py，类 SubjectErasureLedger，负责按分片下发删除、跟踪回执与残留判定。

公开接口：SubjectErasureLedger(*, shards=("blob","index","audit"), max_attempts=3)；submit_request(subject_id, generation, *, now)；dispatch(subject_id, generation, *, now)；confirm(subject_id, shard, *, generation, now)；audit_residual(subject_id, shard, *, generation, residual_count, now)；retry(subject_id, shard, *, generation, now)；resume(*, now)；close(subject_id, generation, *, now)；request(subject_id, generation)；residuals()；snapshot()、restore(state)、stats()。拒绝一律抛 ErasureError(code, detail)。

故障与边界：

①请求按 subject_id 与 generation 唯一，重复提交返回同一张票据，submissions 只计一次；请求号按 era-0001 递增，空主体或 generation 小于 1 报 ERASURE_INVALID_REQUEST；

②提交时为每个分片建一条 pending 任务，任务键为 subject、shard、generation，票据内任务按分片升序，重复下发不得产生第二份；

③dispatch 只把 pending 推成 dispatched，返回 created 与 existing 两个升序清单，清单内不得重复，每次调用都计入 dispatches，即使没有新任务；

④未下发就确认报 ERASURE_NOT_DISPATCHED；未知主体或分片分别报 ERASURE_UNKNOWN_SUBJECT、ERASURE_UNKNOWN_SHARD；

⑤并发重复确认幂等，只记一次 confirmations，其余进 duplicate_confirmations，确认时间以第一次为准；

⑥所有分片确认后才能 close，否则 ERASURE_NOT_COMPLETE；关闭后状态 closed 并写 closed_at；

⑦retry 递增 attempts 并保持任务可重发，重试后任务仍为 dispatched，未到上限不得判成功；

⑧resume 只返回未确认的分片，按主体、分片升序，已确认的不得重复下发；

⑨分片回执声明已删除但复核仍能查到记录（residual_count 大于 0）时，任务回到 pending，不能算完成；

⑩同一主体删除完成前重新注册，新 generation 的数据不受旧任务迟到回执影响，回执 generation 不匹配报 ERASURE_GENERATION_MISMATCH；

⑪超过 max_attempts 仍无响应的任务标记为不可闭合残留并升级人工，close 报 ERASURE_RESIDUAL_UNCLOSABLE，residuals 能查到；

⑫快照字段固定 version、next_request、requests、tasks、stats，结构不合法报 ERASURE_SNAPSHOT_INVALID 且原状态不变。

分片清单在构造时固定，运行中不接受新增分片；任务重发沿用原任务键，不得生成新票据。复核残留由调用方给出数量，台账只按数量判定，任务状态与票据状态必须互相自洽。票据状态为 new、in_progress、residual、closed，任务状态为 pending、dispatched、confirmed、residual_unclosable。

统计口径：stats 固定返回 submissions、dispatches、confirmations、duplicate_confirmations、retries、reopened、escalated、closed。

硬约束：并发确认幂等、计数不得重复；进程重启后 resume 从快照继续推进且不重复下发已确认分片；单主体的任务数按分片数硬顶。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或用固定输入写死；并发与重启自行验证；只做本地实现，运行时不连接真实存储，回执由调用方显式提交。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: subject_erasure_ledger
- typeName: SubjectErasureLedger

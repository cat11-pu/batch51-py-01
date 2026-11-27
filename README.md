# batch51-py-safety-c-28

## 题面

限速复测这周对不上账：同一个接口，一组人报“绕过了限速”，另一组复测完全没复现；回看记录才发现，一半的变体只是把路径大小写改了、末尾补了斜杠，另一半是百分号编码过的路径，却被当成三个独立端点各配了一份预算；还有人在两次窗口测量结果互相打架时直接下了绕过结论。范围是 gsb/batch51-py-safety-c-28 下的 throttle_bypass_prober.py，类 ThrottleBypassProber，负责对同一逻辑端点生成路径变形、判断变体是否共享计数桶，并在预算内安排探测。

公开接口：ThrottleBypassProber(*, total_budget=24, window_rate=4, window_seconds=10)；add_endpoint(endpoint_id, *, path, params=())；remove_endpoint(endpoint_id)；plan_variants(endpoint_id)；dedupe(variants)；classify_counter(endpoint_id, observations, *, decode_before_route=False)；measure_window(endpoint_id, window_index, responses)；compare_windows(first, second)；conclude(endpoint_id, reports)；reserve_probe(endpoint_id, *, at=0)；describe_endpoint(endpoint_id)；snapshot()；restore(state)；stats()；reset()。拒绝时抛 ThrottleError(code, detail)。

要修的行为：①add_endpoint 要求路径以斜杠开头且不含问号与井号，params 为二元组序列，标识重复抛 THROTTLE_DUPLICATE_ENDPOINT，路径或参数非法抛 THROTTLE_INVALID_ENDPOINT。②plan_variants 固定产出五类变体：plain 用原路径与原查询串；case 把路径整体换大小写；trailing_slash 在路径末尾补一个斜杠；encoding 把最后一段首字符换成小写百分号编码；param_order 把查询参数倒序；变体标识为“端点#类别”。③dedupe 以去掉末尾斜杠后的路径加原查询串为键，重复只保留首次出现，顺序不变。④classify_counter 按观测里的计数桶判定：与 plain 同桶记 protected，与 plain 不同桶记 bypass；观测必须包含 plain 变体，未知变体抛 THROTTLE_UNKNOWN_VARIANT。⑤measure_window 统计每个变体的响应次数，状态 429 的变体进 exhausted 清单，返回端点、窗口号、计数、限速清单与总数；窗口号为负抛 THROTTLE_INVALID_WINDOW。⑥compare_windows 比较两次测量里限速清单的差异，返回不一致的变体标识并按升序排列；两次测量不属于同一端点抛 THROTTLE_WINDOW_MISMATCH。⑦reserve_probe 先看总量再看窗口配额，任一项耗尽都不扣减，返回 allowed、reason、剩余总量与剩余窗口额度；未知端点抛 THROTTLE_UNKNOWN_ENDPOINT，at 为负抛 THROTTLE_INVALID_WINDOW。⑧编码变形在服务端解码后才路由时按同一端点计数，不得因为请求行不同就判成独立桶。⑨同一变体在两次窗口测量中结果不一致时按不稳定记录，结论里不得计入绕过。⑩快照返回 version、endpoints、budget、windows、stats 五项且为深拷贝，恢复后端点、预算余量与测量记录原样往返，结构不符抛 THROTTLE_SNAPSHOT_INVALID 且当前状态一字不动。⑪describe_endpoint 返回 endpoint_id、path、params、probes 四个字段，probes 为该端点已生成变体数。⑫stats 返回 endpoints、planned、reserved、denied、measurements、restores，其中 planned 为 plan_variants 累计产出的变体数。

硬约束：同一实例被多个线程同时规划与预留时，预算余量不得被扣成负数，单次预留必须原子判定；总量是硬顶，窗口切换只恢复窗口额度不恢复总量；恢复后余量要能继续按原节奏扣减。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: throttle_bypass_prober
- typeName: ThrottleBypassProber
- file: throttle_bypass_prober.py

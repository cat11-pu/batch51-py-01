# batch51-py-safety-c-27

## 题面

演练编排这周出了两次静默事故：两条破坏性动作先后打到同一台核心交换机，中间只隔几十秒，第二台的配置被回滚脚本洗掉；另一头，一个动作的维护窗早就关了，调度器还在往下发步骤，最后一步落在业务高峰。事后核对发现，调度器既没有按资产把破坏性动作串起来，也没有把维护窗当成硬门禁，取消路径更没把占位清干净，三个问题叠在一起才让两次动作撞到了同一台设备。范围是 gsb/batch51-py-safety-c-27 下的 redteam_action_scheduler.py，类 RedteamActionScheduler，负责按资产互斥、维护窗与取消语义编排演练动作。

公开接口：RedteamActionScheduler(*, max_actions=32, max_steps=8)；enqueue(action_id, asset_id, *, mode="destructive", window_start=0, window_end=10, steps=())；acquire_asset(action_id, *, at=0)；release_asset(action_id)；cancel(action_id, *, at=0)；dispatch_step(action_id, step)；steps_for(action_id)；active_for(asset_id)；timeline()；state_of(action_id)；snapshot()；restore(state)；stats()；reset()。拒绝时抛 SchedulerError(code, detail)。

要修的行为：①enqueue 要求动作与资产标识非空且唯一，mode 只允许 destructive 与 readonly，窗口结束必须大于开始，违反分别抛 RT_INVALID_ACTION、RT_DUPLICATE_ACTION、RT_INVALID_MODE、RT_INVALID_WINDOW。②同一资产同一时刻只允许一个 destructive 处于占用，取得成功时 granted 为 True、reason 为 granted；第二个 acquire 返回 granted 为 False、reason 为 asset_busy，且不得出现在 active_for 里。③readonly 与 destructive 可以并存，多个 readonly 之间也能并存，active_for 按动作标识升序返回。④动作只有在 [window_start, window_end) 内才能取得资产，早于开始或到达结束都返回 window_closed，不占用也不改状态。⑤已在占用的动作重复 acquire 返回 granted 为 True、reason 为 already_held，时间线不得重复追加；release_asset 只释放本动作的资产，未占用或未知动作返回 False，释放后状态为 done，再 acquire 抛 RT_ACTION_CLOSED。⑥cancel 要释放已占资产、清空本动作已下发的步骤，返回 released 标记与丢弃步骤元组，状态置 cancelled；重复 cancel 幂等，返回 released 为 False、丢弃步骤为空，且不再计数。⑦已取消动作再 acquire 或 dispatch_step 抛 RT_ACTION_CANCELLED。⑧timeline 只列取得过资产的动作，按 started_at 升序、同一时刻按动作标识升序，行内带资产、模式与当前状态，取消只改状态不改已记录的开始时刻。⑨动作总数受 max_actions 硬顶、单动作已下发步骤受 max_steps 硬顶，超出抛 RT_CAPACITY_EXCEEDED 或 RT_STEP_LIMIT，且不追加任何状态；dispatch_step 返回追加后的步骤元组，state_of 对未知动作返回 None。⑩动作在等待资产期间被取消时不得留下占位，同一资产后面的动作应当立即取得许可。⑪两条动作声明的维护窗部分重叠、又争同一资产时，按 window_start 与入队序判定先后，后到者不得插队。⑫快照返回 version、actions、active、timeline、stats 五项且为深拷贝，恢复后动作、状态、占用、步骤与计数原样往返，结构不符抛 RT_SNAPSHOT_INVALID 且当前状态一字不动；stats 返回 enqueued、granted、blocked、released、cancelled、dropped_steps、restores。

硬约束：acquire、release、cancel 可能来自不同线程，同一资产的互斥判定必须原子，active 集合不能出现半个动作；时间线一旦写入就不可回改；动作与步骤数量都是硬顶。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: redteam_action_scheduler
- typeName: RedteamActionScheduler
- file: redteam_action_scheduler.py

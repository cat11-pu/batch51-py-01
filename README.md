# batch51-py-safety-c-39

## 题面

沙箱值守这周连开三张误判单。样本 A 在沙箱里先睡了两分钟再正常干活，平台直接判规避分析，客户拿着报告来解释；样本 B 的采集代理半路崩了，轨迹只写到一半，平台照样出了未规避的结论，后来在真机上抓到了虚拟机探测；样本 C 每隔两百毫秒轮询一次键盘状态，被累加成睡眠信号，分数虚高到顶格。范围是 gsb/batch51-py-safety-c-39/sandbox_evasion_classifier.py，类 SandboxEvasionClassifier，负责从轨迹事件与环境探针判定样本是否在规避分析。

公开接口：SandboxEvasionClassifier(*, window_ms=5000, max_events=512, max_indicators=32, indicators=None)；add_indicator(name, category, weight, confidence)；ingest_event(sample_id, kind, *, key="", ts_ms=0)；evaluate(sample_id)；explain(sample_id)；mark_truncated(sample_id, reason="")；reset(sample_id)；snapshot()；restore(state)；stats()；模块级 effective_score(weight, confidence) 与 classify_score(score, categories, *, truncated=False)。异常统一 SandboxError(code, detail)。

要修的行为：①内建指标七条：sleep_long 时序 30/0.5、timing_poll 时序 20/0.5、env_vm 环境 25/0.8、debugger_attach 环境 35/0.9、no_input 交互 20/0.6、name_blocklist 身份 40/0.9、module_blocklist 身份 30/0.8，单条有效分是 weight 乘 confidence 向下取整；②同一指标同一 key 在 window_ms 内只计一次，重复事件返回首次命中的 Hit，时间差达到窗口才重新计，不同 key 分别计数；③类别得分取该类别下已命中指标有效分的最大值，不按命中次数累加，重复命中只抬 hits 计数不抬分数，总分是各类别得分之和且封顶 100；④0 到 19 分判 clean，20 到 69 分判 suspicious，70 分以上且至少两个类别才判 evasive，只有单一类别时最高只能是 suspicious；⑤新增指标校验名称唯一、weight 为 1 到 100 的整数、confidence 大于 0 且不超过 1、名称与类别非空，重复名称报 SANDBOX_INDICATOR_EXISTS，其余非法报 SANDBOX_INDICATOR_INVALID，总数超过 max_indicators 报 SANDBOX_INDICATOR_LIMIT，构造时内建数量已超上限也照此报；⑥每个样本事件数硬顶 max_events，超限报 SANDBOX_TRACE_LIMIT，重复事件不占额度；⑦样本标识为空或非字符串报 SANDBOX_SAMPLE_INVALID，时间戳为负或 key 非字符串报 SANDBOX_EVENT_INVALID，未注册指标报 SANDBOX_UNKNOWN_INDICATOR，未知样本报 SANDBOX_SAMPLE_UNKNOWN；⑧explain 返回 score、verdict、hits、categories 与 top，categories 每项含 hits、score、indicators 并按类别名排序，top 是指标名按有效分降序、同分按名称升序的列表；⑨reset 清空该样本的事件与命中并返回清掉的命中数，计数 resets 加一；⑩mark_truncated 记录原因，之后该样本的结论降级为 uncertain，分数照常算但不改判；⑪stats 返回 samples、hits、duplicates、truncated、resets；快照保存指标表与样本命中，必须深拷贝，非法结构报 SANDBOX_SNAPSHOT_INVALID 且原状态一字不改。同一 API 的短时轮询与长睡眠必须分开计分，轮询不得累加成睡眠信号。

硬约束：同一窗口内同一信号的并发 ingest 只能记录一次，命中与去重计数不得丢；快照恢复后指标表、样本命中与计数可往返，样本之间互不影响，重置一个样本不得清掉其它样本的命中；同一份轨迹重复评估两次，分数与结论必须一致。

Hit 含 indicator、category、key、ts_ms、effective，Verdict 含 score、verdict、categories、hits、truncated，categories 是参与计分类别名的升序元组。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。交付改好的源码与自测输出，说明每处改动的触发条件。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: sandbox_evasion_classifier
- typeName: SandboxEvasionClassifier

# batch51-py-safety-c-31

## 题面

巡检平台这周连出三张对不上的工单。一张说某个查询参数已确认模板注入，值班按结论封了接口，事后复核发现后端只是把 `{{7*7}}` 转义成实体后原样回显；另一张说同一个接口没有注入，可抓包里响应已经把 49 算出来了，探针却停在第 1 条表达式上再没动作；第三张是两个不同参数共用了一份进度，先探的那条命中后，后探的那条直接显示"已排除"。追下来是三件事：回显形态没分类，响应里出现载入的字符就算命中；阶梯不会前进，也不会因为算出结果而停下；进度只按引擎存了一整份，没有按注入点分开。范围是 gsb/batch51-py-safety-c-31 下的 ssti_probe_sequencer.py，类 SstiProbeSequencer，负责按注入点维护表达式阶梯、判定回显形态并记录命中。

公开接口：SstiProbeSequencer(*, max_points=32, max_escalations=4, ladders=None)；register_point(param, *, engine="generic")；points()；ladder_for(param)；expected_marker(payload)；next_payload(param)；evaluate_echo(param, payload, response_text)；detect_context(param, response_text)；context_for(param)；escalate(param)；mark_hit(param)；is_exhausted(param)；reset_point(param)；snapshot()；restore(state)；stats()。拒绝时抛 SstiError(code, detail)，code 为大写串。

要修的行为：① 阶梯内建 generic、jinja2、thymeleaf、erb 四族，generic 依次为 {{7*7}}、${7*7}、<%= 7*7 %>、#{7*7}，jinja2 为 {{7*7}}、{{'7'*7}}；按族取阶梯，未注册的族抛 SSTI_ENGINE_UNKNOWN；② expected_marker 从载荷推出期望回显，算术取乘积，7 乘 '7' 取七个 7 连写，推不出的载荷抛 SSTI_PAYLOAD_OPAQUE；③ next_payload 按阶梯顺序逐条下发，返回 {"point","step","payload"}，step 从 1 起，走完最后一条后返回 None 并置 is_exhausted；④ 参数先去首尾空白再当标识，为空或非字符串抛 SSTI_INVALID_POINT，同一参数重复注册只返回原标识、不新建、不动阶梯；⑤ 注入点数量硬顶 max_points，超限抛 SSTI_POINT_LIMIT，已有注入点不受影响；⑥ evaluate_echo 分四类：响应里出现期望回显且不在模板定界符内判 evaluated；整串载荷原样出现判 raw；实体转义后出现判 escaped；都没有判 absent，raw、escaped 分别计数；⑦ 只有 evaluated 才置命中并关闭该注入点，关闭后 next_payload 返回 None、重复 mark_hit 返回 False；⑧ raw、escaped、absent 一律不置命中，需显式 escalate 前进一条并返回新 step，命中点 escalate 抛 SSTI_POINT_CLOSED；⑨ 阶梯走完再 escalate 抛 SSTI_LADDER_EXHAUSTED；⑩ detect_context 把回显位置分成 text、attr、script，识别不出归 unknown，未探测前 context_for 也返回 unknown；⑪ 阶梯深度受 max_escalations 约束，ladder_for 只返回截断后的有效阶梯；⑫ 未知注入点做 next_payload、evaluate_echo、escalate、context_for 一律抛 SSTI_POINT_UNKNOWN。

两处容易漏的判定单独说清：表达式只被算了一半、结果又被转义输出时按 escaped 处理，不得升级为命中；同一参数的上下文在多次请求之间发生变化时以最近一次判定为准，历史阶梯进度不得直接沿用。

硬约束：同一注入点并发取载荷时同一条表达式只能被一个调用方领到，step 不得回退，命中与关闭要么都生效要么都不生效；snapshot 为 {"version","points","stats","ladders"} 且必须深拷贝，points 每项含 engine、step、context、hit、exhausted，restore 之后阶梯位置、命中态、计数可往返，非法结构抛 SSTI_SNAPSHOT_INVALID 且原状态一字不动。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: ssti_probe_sequencer
- typeName: SstiProbeSequencer

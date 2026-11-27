# batch51-py-safety-c-30

## 题面

参数污染专项这周交上来的结论互相打架：同一个搜索参数，前端取到第一个值、后端取了最后一个，报告只写了一句“疑似污染”，复现时两边都说不清用的是哪一路取值；另一个案例里，同名参数同时出现在查询串和请求体，被合成一条结论，修复方按查询串改完，请求体那条路照样被覆盖；还有空值和参数缺失被混为一谈，误判了一批本来正常的接口。范围是 gsb/batch51-py-safety-c-30 下的 param_pollution_scanner.py，类 ParamPollutionScanner，负责构造重复参数矩阵、归一解析口径并合并结果。

公开接口：ParamPollutionScanner(*, max_combos=24, max_params=6)；add_endpoint(endpoint_id, *, path, params=())；remove_endpoint(endpoint_id)；build_matrix(endpoint_id)；classify_parser(values, resolved)；param_state(*, present, value)；compare_backends(frontend, backend)；record(probe_id, *, source, frontend, backend)；merge(results=None)；describe_endpoint(endpoint_id)；results_for(probe_id)；snapshot()；restore(state)；stats()；reset()。拒绝时抛 ParamError(code, detail)。

要修的行为：①add_endpoint 要求路径以斜杠开头且不含问号，参数为二元组序列且不超过 max_params，标识重复抛 PARAM_DUPLICATE_ENDPOINT，路径或参数非法抛 PARAM_INVALID_ENDPOINT，参数超量抛 PARAM_TOO_MANY_PARAMS。②build_matrix 对每个参数按固定顺序产出六类探测：duplicate_first 为原值在前、探针值在后；duplicate_last 为探针值在前、原值在后；bracket_dup 用方括号键重复两次；scalar_then_array 先标量后数组；encoded_sep 把第二个键值用百分号编码的 & 拼进值里；semicolon_sep 用分号拼进值里；探测标识为“端点:参数:类别”。③参数按名字升序排列，矩阵总量受 max_combos 硬顶，超出不生成并计入 suppressed；未知端点抛 PARAM_UNKNOWN_ENDPOINT。④classify_parser 按后端实际取值归一口径：等于首个值记 first，等于末个值记 last，等于值列表记 array，等于逗号连接结果记 joined，取不到值记 none，其余记 other；values 为空或含非字符串抛 PARAM_INVALID_VALUES。⑤compare_backends 两侧一致记 consistent，两侧都取不到记 consistent，只有一侧取不到记 divergent_missing，其余不等记 polluted。⑥record 记录单次探测结果，来源只接受 query 与 body，未知探测抛 PARAM_UNKNOWN_PROBE，非法来源抛 PARAM_INVALID_SOURCE，可对同一探针同一来源重复记录多次。⑦merge 以参数、类别与来源为键，取最强结论（polluted 强于 divergent_missing，强于 consistent），行内带观测次数，按参数、类别与来源升序；重复掉的条数记在 merged。⑧参数值为空串与参数缺失在部分后端等价，判定时要分开记录，不得合并成同一条结论。⑨同一参数同时在查询串与请求体出现时按来源分别归类，不得合并成一条结论。⑩快照返回 version、endpoints、probes、results、stats 五项且为深拷贝，恢复后端点、矩阵、结果与计数原样往返，结构不符抛 PARAM_SNAPSHOT_INVALID 且当前状态一字不动。⑪describe_endpoint 返回 endpoint_id、path、params、probes 四个字段，params 为按名字升序的二元组，probes 为该端点已生成探测数；results_for 返回该探测的全部记录。⑫stats 返回 endpoints、probes、suppressed、results、merged、restores，其中 probes 为累计生成的探测数。

硬约束：探测总量是硬顶，任何参数组合都不能突破；多线程同时构造矩阵与记录结果时，计数与结果列表必须原子更新，不得丢记录；恢复后矩阵与结果要和中断前一致。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: param_pollution_scanner
- typeName: ParamPollutionScanner
- file: param_pollution_scanner.py

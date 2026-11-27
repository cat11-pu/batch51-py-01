# batch51-py-safety-c-36

## 题面

门禁灰度后前端集体白屏，监控同时刷出三类工单。第一类：同一段脚本，只有 default-src 的老页面照常放行，补上 script-src 之后整站被拦，回滚脚本又把权限放大回原样。第二类：带 nonce 的内联脚本在样式里能用，同一个 nonce 换到图片上却被当成合法来源放行。第三类：一次响应同时下发两份策略头时，report-only 那份把已经被放行的资源全记成违规，一晚上刷出几万条，值班只能先关监控。追下来是解析、回退链与多策略合并三处各算各的，没有统一求值。范围是 gsb/batch51-py-safety-c-36/csp_policy_evaluator.py，类 CspPolicyEvaluator，负责解析 enforce 与 report-only 两份策略并判定资源能否放行。

公开接口：CspPolicyEvaluator(*, origin="")；parse_policy(text, *, mode="enforce", name="policy")；register_policy(policy)；evaluate(policy, *, url, kind="script", nonce=None, hashes=())；merge_policies(policies)；check_nonce(policy, *, directive, nonce)；report(decisions)；snapshot()；restore(state)；stats()；模块级 effective_directive(directives, kind) 与 source_matches(expression, url, *, origin="")。异常统一 CspError(code, detail)。

要修的行为：①指令名一律转小写、键按键字典序排列，来源保留书写顺序，空段直接忽略；②文本超过 4096 字符、去重后指令超过 32 条、mode 不是 enforce 与 report-only、整份为空，分别报 CSP_POLICY_TOO_LARGE、CSP_TOO_MANY_DIRECTIVES、CSP_MODE_INVALID、CSP_POLICY_EMPTY；③同名指令只认第一次出现的那条，'none' 与其他来源混用报 CSP_DIRECTIVE_INVALID；④回退链 script 依次为 script-src-elem、script-src、default-src，style 同构，img 依次为 img-src、default-src，链路全缺时放行且 directive 为 None，未知 kind 报 CSP_KIND_INVALID；⑤来源匹配支持 'self'、scheme:、主机、*.子域以及端口与路径前缀，裸主机只匹配自身，通配不得跨主机，* 只匹配 http 与 https，多条来源命中时取书写顺序里的第一条，matched 返回该来源原文；⑥有效指令里出现 nonce 或 hash 时 'unsafe-inline' 失效，内联资源只能凭 nonce 或 hash 放行；阻断原因取 none 表示被 'none' 拦住、source 表示没有来源匹配、inline 表示内联被挡；⑦'strict-dynamic' 让脚本的主机与 scheme 来源失效，样式不受影响；⑧多份策略取交集，任一 enforce 拒绝即拒绝，blocked_by 按顺序列出拒绝方，report-only 只记录不阻断，merge_policies 混入非 Policy 对象报 CSP_POLICY_INVALID，PolicySet 的 digest 由 name:mode 组成，enforce 段在前、report-only 段在后，两段用分号隔开、段内用逗号隔开；⑨report 返回 total、allowed、blocked、violations、by_directive、by_policy，后两者按键排序，stats 与快照 counters 的键为 evaluated、allowed、blocked、violations；⑩register_policy 每次把 revision 加一并返回新值；快照为 revision、policies、counters 三项，必须深拷贝，policies 每项含 mode 与 directives，非法结构报 CSP_SNAPSHOT_INVALID 且原状态一字不改。未知指令保留但不参与回退，拼错的指令名不得让 default-src 失效。

另有两处容易漏：同一响应带 enforce 与 report-only 两份策略时，report-only 的违规要按 enforce 的结果去重，被 enforce 放行的资源不得记成违规；nonce 只对脚本与样式生效，出现在 img-src 时按无效来源处理而不是放行。

硬约束：求值之间不共享可变状态，多线程并发 evaluate 的计数不得丢、不得重；快照恢复后 revision、策略与计数可往返，恢复失败不得污染现有状态。服务重启后 revision 归零，同一份策略重新注册又被算成新版本，排查时对不上号，这个也要一并修掉。

Policy 含 name、mode、directives，PolicySet 含 enforce、report_only、digest，Decision 含 allowed、directive、matched、violations、blocked_by，Violation 含 policy、directive、blocked_uri、reason。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。交付改好的源码与自测输出，说明每处改动的触发条件。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: csp_policy_evaluator
- typeName: CspPolicyEvaluator

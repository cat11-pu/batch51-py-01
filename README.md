# batch51-py-safety-a-07

## 题面

密码策略这周被审计挑了三处：同一批口令在短信登录和后台登录拿到不一样的分值和结论；租户把最短长度改到 8 之后，弱口令字典里的词也一起放过去了；策略热更新时，并发请求读到的新旧规则各占一半。复核口径要求每次登录看到的都是同一份合成结果，租户能做的是把策略改严或按场景做有边界的例外，而不是绕开基础规则。范围是 gsb/batch51-py-safety-a-07 的 password_strength_policy_engine.py，类 StrengthPolicyEngine，负责把全局基线、租户策略与场景例外合成为一次检查。

公开接口：StrengthPolicyEngine(*, dictionary=("password","letmein","qwerty"))；set_baseline(overrides)；set_tenant_policy(tenant, overrides)；register_exception(tenant, scenario, overrides, *, exempt=())；compose(tenant, *, scenario=None)；explain(tenant, *, scenario=None)；evaluate(password, *, tenant, username=None, scenario=None)；reload(payload)；policy_version()；snapshot()、restore(state)、stats()。拒绝一律抛 PolicyError(code, detail)。

故障与边界：

①基线键固定 min_length、min_classes、max_repeats、min_score，默认 12、3、2、60；分数从 100 起扣，length 25、classes 20、repeat 15、dictionary 30、username 40，下限 0；

②规则按 length、classes、repeat、dictionary、username 的固定顺序执行，failed 去重且按该顺序排列；passed 要求没有未豁免的失败规则且分数不低于 min_score；

③字典按大小写不敏感的子串命中，命中即记 dictionary 失败；

④租户策略与基线冲突时取更严者：min_length、min_classes、min_score 取大，max_repeats 取小，租户不能放宽基线；

⑤场景例外可以对显式列出的键放宽或收紧，未列出的键沿用合成结果；例外与例外冲突同样取更严者，允许只给 exempt 不给覆盖项；

⑥例外把最小长度降到 8 时，字典与重复字符检查仍然执行，只有 exempt 里点名的规则才允许跳过；

⑦口令包含用户名或其倒序（大小写不敏感）一律不通过，该判定不受租户例外影响；

⑧同一策略版本内重复评估必须逐字段一致，包括失败规则顺序；reload 之后同一口令的结果允许变化；

⑨空口令、非字符串口令、未知规则键、空租户、空场景报 POLICY_INVALID_REQUEST；未单独登记策略的租户按基线合成，只有显式指定的未登记场景才报 POLICY_SCENARIO_UNKNOWN；

⑩reload 只接受完整的 baseline、tenants、exceptions 结构：baseline 必须四键齐全，tenants 是租户到覆盖项的映射，exceptions 是带 tenant、scenario、overrides、exempt 的记录列表；任何一层不合法报 POLICY_PAYLOAD_INVALID，旧版本继续服务；

⑪快照字段固定 version、baseline、tenants、exceptions、stats，结构不合法报 POLICY_SNAPSHOT_INVALID 且原状态不变；

⑫set_baseline、set_tenant_policy、register_exception、reload 成功都使版本号加一，初始版本为 1，compose 返回的 CompositePolicy 带上当时的版本号。

统计口径：stats 固定返回 evaluations、failures、exemptions_applied、reloads。分值只用于排序和提示，是否通过仍以失败规则与阈值共同判定；被豁免的规则既不计失败也不扣分，复核记录要能原样复算。explain 返回 version、tenant、scenario、min_length、min_classes、max_repeats、min_score、exempted，其中 exempted 用列表。

硬约束：重载期间每次评估只能看到完整旧版或完整新版，并发评估同一版本必须结果一致；单次评估不得因为缓存跳过字典检查；快照恢复后基线、租户、例外、版本号与计数完整还原。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或用固定输入写死；并发与重启自行验证；只做本地实现，运行时不得依赖外部服务，字典与例外都在进程内。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: password_strength_policy_engine
- typeName: StrengthPolicyEngine

# batch51-py-safety-c-07

## 题面

值班同事反馈：插同一个 USB 串口设备，节点权限有时是 0600，有时变成 0666；两条规则都写了 NAME，最后只剩一条生效却没有任何记录；规则文件被同组同事改过之后，整机还在按旧规则跑。更麻烦的是热插拔时规则正在重载，同一台设备偶尔只应用了半条规则，名字换了权限没换；同一台设备在两个文件里被写成不同名字，最后哪个生效只能靠猜。范围是 gsb/batch51-py-safety-c-07 的 udev_rule_guard.py，类 UdevRuleGuard，负责解析设备规则、按属性求值并输出最终节点名、权限、属主、标签与软链接。

公开接口：UdevRuleGuard(*, max_rules=4096, allow_run=False)；load_rules(files)；rules()；match_rule(rule, attrs)；evaluate(device_id, attrs)；simulate(devices)；audit()；conflicts()；set_allow_run(enabled)；snapshot()；restore(state)；stats()。files 是 RuleFile(source, mode, text) 序列，rule 是解析后的 Rule；拒绝抛 UdevError(code, detail)。

要修的行为：①按文件顺序与行序解析，注释与空行跳过，行号从 1 起算且包含空行与注释行；②匹配键支持 SUBSYSTEM、KERNEL、DRIVER、TAG 与 ATTR{...}，赋值键只允许 NAME、MODE、OWNER、GROUP、SYMLINK、TAG、RUN，其他键整份拒绝并报 UDEV_RULE_SYNTAX；③同一条规则内多个匹配键是逻辑与，任一不满足整条跳过，赋值项不得部分生效；④规则按装载顺序求值，后匹配的赋值覆盖先前同名项，MODE 按八进制解析成整数，非法八进制使整份装载失败并保留原有规则；⑤NAME 赋重名时后者覆盖前者并记一次冲突，不能两条都保留，冲突记录要写清设备、新旧规则号与两个取值；⑥TAG 与 SYMLINK 走 += 累加，按首次出现顺序去重；⑦RUN 默认拒绝，只记一次拒绝计数，allow_run 打开后才收集命令；⑧规则文件权限为组可写时必须整份拒绝加载并报 UDEV_FILE_INSECURE，不能只跳过可疑行；⑨规则总数超 max_rules 报 UDEV_CAPACITY_EXCEEDED，超限时整份新规则都不生效；⑩simulate 只算不落账，不改计数也不写审计，审计按求值顺序追加、可逐台复盘；⑪stats 返回 rules、reloads、evaluations、matches、run_denied、conflicts 六项；⑫快照为 dict 深拷贝，含 version、rules、allow_run、counters、audit、conflicts，counters 为 dict，调用方就地清空或改写任一表都不得影响运行中的状态，缺字段或类型不对报 UDEV_SNAPSHOT_INVALID 且不动现存状态；装载失败时上一份规则、计数与审计都要原样保留。规则序号从 0 起按装载顺序递增；evaluate 返回 DeviceResult(device_id、name、mode、owner、group、tags、symlinks、commands、matched_rules)，审计条目记设备、命中的规则号、实际生效的键与拒绝计数。MODE 结果统一用整数返回，OWNER 与 GROUP 用字符串。

硬性约束：并发重载与求值同时发生时，求值只能看到完整旧规则集或完整新规则集，不能出现半套规则，也不能一条规则命中一部分赋值；装载失败保留上一份规则，节点命名与权限查询不得清空，重启恢复后规则、审计与计数一并还原；同一份规则重复装载要得到逐字段一致的解析结果，不依赖字典遍历顺序；规则集与审计条数设上限，超限报错不静默扩容。

验收：python3 -m pytest -q tests 跑满 15 条用例全过；测试不许改、不许跳过、不许按固定输入写死；并发重载自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: udev_rule_guard
- typeName: UdevRuleGuard

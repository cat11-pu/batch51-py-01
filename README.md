# batch51-py-safety-r-08

## 题面

代码仓库的合规扫描连续两周漏报：业务方把一个云厂商的访问密钥贴进了配置文件，扫描器因为串太短直接跳过；同一份密钥后来在三个文件里出现，报告却只列了第一次命中的那一处，工程师按报告清理完还以为干净了；另一次更离谱，某个占位符被报成高危，真正的高熵串反而躺在白名单里没人看。现在要重做扫描器的核心。范围是 gsb/batch51-py-safety-r-08 的 secret_entropy_scanner.py，类 SecretEntropyScanner，负责分词、熵计算、规则匹配、占位符排除、命中归并与报告排序。

公开接口：SecretEntropyScanner(*, rules=None, min_length=8, max_token_length=512)；entropy(text)；tokenize(text)；is_placeholder(token)；match_rule(token)；scan_text(text, *, path, commit=None)；scan_files(files, *, commit=None)；findings()；findings_for(rule)；report()；add_rule(name, *, prefix=None, min_length=8, max_length=None, min_entropy=3.5, severity="medium")；stats()；snapshot() 与 restore(state)。参数非法或快照损坏抛 ScanError(code, detail)。

要修的故障与边界：①候选串由字母、数字、下划线、连字符、加号、斜杠组成，遇到其他字符断开；长度达到 min_length 才进候选，超长按上限截断；line 与 column 都从 1 计，column 是串在行内的起始列。②熵按字符分布算香农熵，空串记 0，结果四舍五入到 6 位小数。③占位符先排除：词表里的词大小写不敏感地整串命中即排除，字符种类少于 3 的退化串也按占位符处理。④规则按声明顺序匹配，前缀、长度区间、最小熵三项全中才算命中，第一个命中的规则生效，同一串不会同时属于两条规则。⑤命中证据只留前 4 位加三个星号的预览与指纹，报告里不得出现完整凭据。⑥同一规则下同一个串重复出现只保留最早一条，重复次数单独计数，命中总数按保留后的条数算。⑦报告按严重度从高到低排，同级按路径、行号、列号、规则名升序。⑧scan_files 按传入顺序扫描，scan_text 与 scan_files 都计入扫描次数与候选数。⑨同一凭据在不同提交里出现时只保留最早一条，但每个文件里的命中位置都要记下来。⑩高熵但明显是哈希值或测试向量的串要按上下文排除，不能只看字符集。⑪熵值刚好等于阈值时按命中处理，阈值比较不能因为浮点误差抖动。⑫自定义规则追加在内置规则之后，同样参与匹配与报告排序；findings_for 只按规则名过滤，未知规则返回空元组。

硬约束：扫描、归并与计数持同一把锁串行，多线程并发扫描时命中与计数不得交叉写坏；快照深拷贝规则、命中、去重索引与计数，恢复后同一份文本的扫描结果与恢复前一致，非法快照整份拒绝且不动现有状态；候选长度上限与规则的长度区间都是硬顶。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发扫描与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: secret_entropy_scanner
- typeName: SecretEntropyScanner

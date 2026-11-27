# batch51-py-safety-c-33

## 题面

上个月私服镜像里躺着一个叫 requests 的包，首字母 r 是西里尔字母，页面看上去毫无差别，装它的服务把内网凭证发去了外部域名；同一批还有 requesys、flaskk 这种键盘误敲的名字，两个月没人发现。现在的检查只在一张静态名单上做完全相等比对，改一个字符就放过去；名单里删掉的包，历史命中记录也一起消失了，值班回头查不到当时是谁报的。范围是 gsb/batch51-py-safety-c-33 下的 package_typosquat_index.py，类 PackageTyposquatIndex，负责为受关注包名建立相似度索引、按阈值分级返回候选并留下观测记录。

公开接口：PackageTyposquatIndex(*, max_watches=64, high=0.90, near=0.80)；add_watch(name, *, ecosystem="pypi")；remove_watch(name)；watches()；similarity(left, right)；classify(incoming)；candidate(incoming, *, limit=3)；observe(incoming)；history_for(watched)；snapshot()；restore(state)；stats()。拒绝时抛 TyposquatError(code, detail)，code 为大写串。

要修的行为：① add_watch 先归一：去首尾空白、转小写、下划线与点一律换成连字符、连续连字符合并、去掉首尾连字符；归一后为空、非字符串或超过 64 字符抛 TYPO_INVALID_NAME；② 同一归一名称重复加入只返回原名称、不重复计数，watches 按字典序返回；③ 关注名单硬顶 max_watches，超限抛 TYPO_WATCH_LIMIT，已有条目不受影响；④ remove_watch 返回是否真的删掉，重复删返回 False，删除后不再出现在 watches，删除计数只加一次；⑤ similarity 用加权编辑距离：插入与删除各记 1，替换时两个字符若在同一键盘行且相邻只记 0.5，其余记 1，得分是 1 减去代价再除以两者较长长度、保留四位小数，两侧归一后相同直接返回 1.0；⑥ classify 返回 {"level","package","similarity"}，归一后与某关注名完全一致判 exact；否则取相似度最高的关注名，达到 high 判 high，达到 near 判 near，都不到判 far 且 package 为 None；⑦ candidate 只返回相似度达到 near 且不是 exact 的条目，按相似度降序、同分按包名升序，limit 是条数上限，0 返回空列表；⑧ observe 把来料名记到每个命中的关注名名下，返回 {"recorded","package","level","similarity"}，recorded 按包名升序，同一来料重复观测只记一次；⑨ history_for 按字典序返回该关注名的历史来料，未知名称返回空列表；⑩ 归一与比较不得改写调用方传入的字符串，也不得因为大小写或首尾空白产生重复关注名；⑪ 每个关注名只维护一份索引条目，add_watch 与 remove_watch 之后条目数必须与 watches 长度一致；⑫ snapshot 为 {"version","watches","history","thresholds","stats"}，restore 遇字段缺失或类型不符抛 TYPO_SNAPSHOT_INVALID 且原状态一字不动。

两处容易漏的判定单独说清：同形字按统一编码归并后与原包名完全相同的候选要单列 critical，不得与一般近似一起并进 high 或 near；被监视包名删除后，它的历史来料仍然可查，但不再参与任何新的比对，索引里不得留下指向已删名称的悬挂条目。

硬约束：并发执行 add_watch、remove_watch 与新来料的比对时，任一次查询要么看到删除前的完整索引、要么看到删除后的完整索引，不能出现条目数与 watches 长度对不上的中间态；相似度索引是内存结构，关注名单是硬顶，任何路径都不得越界；snapshot 必须深拷贝，restore 之后关注名、历史来料、阈值与全部计数可往返。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: package_typosquat_index
- typeName: PackageTyposquatIndex

# batch51-py-safety-c-34

## 题面

客服系统的外链白名单上线三个月被绕了两次。第一次，跳转参数写成 `//evil.example.com/x`，白名单只比对 `https://` 开头的整串，协议相对写法直接通过；第二次，参数写成 `https://whitelisted.example.com@evil.example.com/cb`，`@` 前面那一截正好是白名单里的域名，字符串前缀比对又放过去了，浏览器最后落在后面那个站点。还有一条内部投诉：跳转链中间某一跳是空值，校验器把这个空跳跳过去继续看后面两跳，整条链被判成通过。范围是 gsb/batch51-py-safety-c-34 下的 redirect_hop_verifier.py，类 RedirectHopVerifier，负责归一目标、识别协议相对与编码变体、并按白名单逐跳比对。

公开接口：RedirectHopVerifier(*, allowed_hosts=(), allowed_schemes=("https","http"), max_hops=4)；allow_host(host)；allowed_hosts()；normalize_target(target, *, base=None)；check_scheme(target)；is_allowed(target)；verify_hops(targets)；hop_chain()；dedupe(targets)；snapshot()；restore(state)；stats()。拒绝时抛 RedirectError(code, detail)，code 为大写串。

要修的行为：① normalize_target 把 scheme 与 host 转小写、去掉默认端口（http 80、https 443）、反斜杠一律当正斜杠、scheme 与主机之间斜杠不足两条补成两条、路径中连续斜杠压成一条、解析 `.` 与 `..` 路径段、解码主机名里的百分号编码，其他部分原样保留；空串、非字符串、缺 scheme 又没有 base 一律抛 REDIRECT_TARGET_INVALID。② 以 `//` 开头的协议相对目标必须借 base 补出 scheme 与主机，没有 base 按非法目标处理。③ check_scheme 只认 http 与 https 并返回小写 scheme，javascript、data、file 以及不在 allowed_schemes 内的一律抛 REDIRECT_SCHEME_DENIED。④ is_allowed 只做主机全等比对、不做后缀匹配：白名单有 example.com 时不放行 a.example.com，也不放行 example.com.evil.net。⑤ verify_hops 逐跳归一并比对，返回 {"ok","reason","count","denied","hops"}；任一跳不在白名单即停，reason 为 REDIRECT_HOST_DENIED，count 是已通过的跳数，denied 是失败那跳归一后的地址，hops 只收已通过的地址。⑥ 跳数超过 max_hops 即停，reason 为 REDIRECT_HOP_LIMIT，denied 是尚未评估的那一跳，hops 不再加长。⑦ 归一后与链上已有地址重复判 REDIRECT_LOOP，count 与 hops 停在前一跳。⑧ 全部通过时 ok 为 True、reason 与 denied 为 None、count 等于 hops 长度，hop_chain 返回最近一次校验通过的链。⑨ dedupe 按归一后地址去重并保留首次出现顺序，删掉的条数计入统计。⑩ allow_host 归一主机名后加入白名单，allowed_hosts 按字典序返回，重复加入不产生重复项。⑪ 归一过程不得改写调用方传入的字符串，也不得把两个不同站点的地址折成同一个。⑫ snapshot 为 {"version","allowed_hosts","allowed_schemes","max_hops","chain","stats"}，restore 遇字段缺失或类型不符抛 REDIRECT_SNAPSHOT_INVALID 且原状态一字不动。

两处容易漏的判定单独说清：目标里带用户信息段时按 `@` 之后真正的主站判定，不得因为 `@` 之前的字符串落在白名单里就放行；跳转链中某一跳为空值时按终止处理，不得跳过这一跳继续比对后面的地址。

硬约束：白名单增删与校验并发进行时，一次校验只能看到增删前的完整白名单或增删后的完整白名单，hop_chain 要么是上一条完整链要么是当前这条，不能读到写了一半的链；跳数是硬顶，任何路径都不得越界评估；snapshot 必须深拷贝，restore 之后白名单、允许 scheme、跳数上限、最近一条链与全部计数可往返。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: redirect_hop_verifier
- typeName: RedirectHopVerifier

# batch51-py-safety-c-44

## 题面

支付页面上周被安全研究员现场演示了一次点击劫持：攻击者把收银台套进自己的 iframe，用一层透明按钮盖住“确认支付”，用户一点就被扣款。复核时冒出三个互相打架的现象：收银台同时回了两份 X-Frame-Options，一份 DENY 一份 SAMEORIGIN，反向代理又在后面追加了一份，前端只取第一个来测；另一条链路上 XFO 写着 DENY，页面却又上了 CSP 的 frame-ancestors 星号，检查工具把两条取交集，判成了不可嵌入；还有一处写的是 frame-ancestors *.example.com，测试脚本把 example.com 本身也算成了命中。同一个收银台在灰度环境里被三家商户各测了一遍，三种结论互相对不上，复盘会开了两次也没定论，最后只能先把 iframe 全部关掉，支付成功率掉了两个点。

范围是 gsb/batch51-py-safety-c-44，文件名 clickjacking_header_prober.py，主类 ClickjackingHeaderProber，记录类型 HeaderSet、XfoPolicy、FrameAncestors、AncestorChain、FrameVerdict、Probe，异常统一抛 FrameError(code, detail)。

对外接口：ClickjackingHeaderProber(*, fetcher, max_probes_per_target=4, max_redirects=3)；fetch_headers(url)；parse_xfo(headers)；parse_frame_ancestors(headers)；evaluate(url, *, ancestors)；report()；snapshot()；restore(state)；stats()；probe_count(target)；reset()。

需要落实的故障与边界：①头名统一小写、保留原始顺序与重复项，3xx 带 Location 时跟随，最多跟 max_redirects 跳，超出抛 FRAME_REDIRECT_LIMIT；②XFO 只认 DENY 与 SAMEORIGIN，ALLOW-FROM 已废弃按不支持处理并判拒绝，未知取值抛 FRAME_HEADER_INVALID；③CSP frame-ancestors 存在时覆盖 XFO，两者同时出现按 CSP 判，不能取交集，frame-ancestors 存在但没有任何来源算非法，抛 FRAME_HEADER_INVALID；④多个 XFO 头或逗号列表按最严格值生效，反向代理追加的头不能放宽结论；⑤frame-ancestors 的星号、self、scheme、主机与端口逐项求值，主机通配 *.example.com 不匹配 example.com 本身；⑥嵌套祖先链从最外层到直接父级逐层判定，任一祖先不允许即拒绝，evidence.ancestors 保留整条链；⑦重定向后以最终响应头为准，但 hops 保留完整跳转链；⑧错误页与 API 响应同样探测，不按状态码跳过，默认错误页往往正是最容易被套的那一张；⑨无 XFO 且无 frame-ancestors 判 embeddable，理由为 no_protection；⑩SAMEORIGIN 只允许与目标同源，同源按 scheme、主机与端口比较，缺省端口补齐后再比；⑪同一目标探测次数硬顶，超出抛 FRAME_PROBE_LIMIT_EXCEEDED，report 按 origin 归并目标、同一目标取最后一次结论，输出 targets、embeddable、blocked、counts、probes，counts 只含 embeddable 与 blocked 两个键，stats 暴露 probes；⑫同一目标的并发探测必须串行，任意时刻只能有一个请求在途；snapshot 深拷贝 version、probes、verdicts、stats 四个键，restore 遇非法结构抛 FRAME_SNAPSHOT_INVALID 且现场不变。

两条硬约束：并发侧按目标加锁串行，多线程同时探测同一目标不能出现交错的在途请求；恢复侧把快照装到新实例后，探测计数、结论与报告必须与恢复前一致，不能丢也不能重复累计。探测记录按目标与祖先链分别保存，报告只做目标层归并。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: clickjacking_header_prober
- typeName: ClickjackingHeaderProber

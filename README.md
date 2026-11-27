# batch51-py-safety-c-41

## 题面

客服后台这周出了一次很难复现的泄露。攻击者把发票列表地址后面拼上一段 .css 发给值班客服，客服在自己的登录态下点开，页面正常显示；不到一分钟，另一个没有登录的浏览器访问同一个带后缀的地址，拿到的还是那位客服的发票内容，缓存节点上还挂着一条命中记录。复盘时又冒出两种互相矛盾的说法：一处响应头写着 Cache-Control: private，检查脚本据此直接判了安全；另一处第二次请求拿回的是登录页，脚本却按响应长度算成了命中。值班先按 private 把第一条归档成误报，第二天同一路径又被 .js 后缀复现了一遍，大家才承认判断依据从一开始就选错了。

要把这条链路固化成探测器，落在 gsb/batch51-py-safety-c-41，文件名 cache_deception_prober.py，主类 CacheDeceptionProber，记录类型 Response、ProbeVariant、ProbeRecord、ProbeVerdict，异常统一抛 CacheError(code, detail)。

对外接口：CacheDeceptionProber(*, origin, private_prefixes=("/account",), max_probes_per_path=6, max_total_requests=40, cache_key_policy="query_ignored", fetcher=None)；plan(path)；probe(path, *, victim_marker)；verify_cache(probe_id)；classify(probe_id)；cache_key_for(url)；probes_for(path)；report()；snapshot()；restore(state)；stats()；reset()。

需要落实的故障与边界：①变体固定按 .css、.js、.jpg、;.css、%00.css、.Css、/.css 七种顺序生成，路径末尾的斜杠先去掉再拼后缀，同一路径去重，超过 max_probes_per_path 截断；②路径必须落在私有前缀下，/accounting 这类同前缀不同段要拒绝，抛 CACHE_PATH_FORBIDDEN；③受害者私有标记为空、全空白或不是字符串时拒绝，抛 CACHE_INVALID_REQUEST；④首次请求逐个变体带 Authorization: Bearer cache-probe，记录状态、头集合、归一化缓存键与请求计数；⑤缓存键按 CDN 规则归一：主机小写、折叠重复斜杠、去掉尾部斜杠，查询串是否入键由 cache_key_policy 决定，两种策略不能混用；⑥第二次请求必须匿名，Vary 含 Cookie 或星号、Cache-Control 含 no-store 时判不可缓存；⑦响应带 Cache-Control private 或 Set-Cookie 时不能只凭头部判安全，以第二次匿名请求是否命中为准；⑧第二次请求返回登录页或不含私有标记的页面不算命中；⑨Age 与 X-Cache 只能作为证据，单独出现不能判命中，也不能因为第二次响应少了 X-Cache 就反推未命中，证据里的 age 字段记录第二次响应的 Age；⑩classify 在验证前返回 inconclusive/not_verified，验证后返回同一结论，未知 probe_id 抛 CACHE_PROBE_UNKNOWN；⑪report 返回 origin、paths、probes、requests、verdicts（cached、not_cached、inconclusive）与 cached_paths，同一路径探测串行且重复探测复用同一批 probe_id，stats 返回 probes、verifications、requests、cached、not_cached 五项计数；⑫每路径变体数与总请求数硬顶，超限抛 CACHE_LIMIT_EXCEEDED 且不留半截记录；snapshot 深拷贝五个键，restore 遇非法结构抛 CACHE_SNAPSHOT_INVALID 且现场不变。

两条硬约束：同一路径并发探测必须串行，多个线程同时进来只能发出一轮请求；快照恢复到新实例后，已产生的记录、结论与计数必须与恢复前一致，不能丢也不能重复累计。请求预算按实际发出的请求累计，首次探测与匿名验证都要计入。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: cache_deception_prober
- typeName: CacheDeceptionProber

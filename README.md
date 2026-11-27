# batch51-py-safety-c-40

## 题面

资产测绘这周报了三起误报。第一起，扫描器把只编码一次的 ../ 打到会解码两次的网关，请求根本没出去就越界，工具却记了命中，复现时只有双层编码那条能打通；第二起，目标文件不存在，服务端照样返回 200 和首页，工具只看状态码就判了穿越；第三起，同一批变体在 Linux 上跑了三遍，去重后只剩最后一层，服务端两次解码的差异全被吃掉，值班只能先把扫描停了。范围是 gsb/batch51-py-safety-c-40/path_traversal_prober.py，类 PathTraversalProber，负责生成路径穿越变体、对照基线并判定是否越出根目录。

公开接口：PathTraversalProber(*, transport=None, max_requests=64, max_depth=4, signature="root:x:0:0", threshold=16)；generate_variants(depth=2, *, target_file="etc/passwd")；dedupe(variants, *, platform="posix")；send(target, variants)；judge(records)；report(verdicts)；snapshot()；restore(state)；stats()；模块级 variant_key(raw, *, platform="posix") 与 baseline_path(target, length)。异常统一 ProbeError(code, detail)。

要修的行为：①变体共九层，顺序为 plain、backslash、url-encoded、double-encoded、overlong-utf8、semicolon、dot-truncation、unicode-normalized、absolute，前八层的模板依次是 ../、..\、..%2f、%252e%252e%252f、%c0%ae%c0%ae%2f、..;/、.../、%ef%bc%8e%ef%bc%8e%2f，各自重复 depth 次再拼 target_file，absolute 直接拼斜杠加 target_file；②depth 必须是 1 到 max_depth 的整数，否则报 PROBE_VARIANT_INVALID；③dedupe 按 variant_key 保留首次出现且顺序不变，posix 下键就是原串，windows 下按段剥离末尾的点与空格，探测记录仍保留原变体；④send 只接受 http 与 https 目标，否则报 PROBE_TARGET_INVALID，变体列表为空时直接返回空元组且不发请求；⑤每个变体都要配一条等长正常路径的基线，基线路径是 target 去掉尾斜杠后接斜杠再加 length 个 a，基线按 (target, 长度) 在实例内缓存，同一长度只请求一次；⑥单次发送的请求数（基线加变体）超过 max_requests 报 PROBE_REQUEST_LIMIT 且一个请求都不发，传输层抛异常报 PROBE_TRANSPORT_FAILED；⑦judge 依次判定：响应体含目标文件特征（默认 root:x:0:0）判 signature 命中，状态码 403、429 或响应体含 access denied、blocked by waf 判 undecidable，状态码与基线不同且变体为 200、响应体与基线不同、长度差绝对值不小于 threshold 判 length 命中，其余判 none；⑧report 返回 total、hits、misses、undecidable、by_layer 与 hit_keys，by_layer 按层统计命中数并按键排序，hit_keys 为命中变体键的升序列表；⑨stats 返回 generated、sent、requests、hits，被拒绝的发送不增加 sent，requests 只统计真正发出的请求；快照保存 baselines、probed 与 counters，必须深拷贝，非法结构报 PROBE_SNAPSHOT_INVALID 且原状态一字不改。

另有两处容易漏：服务端解码两次时单层编码可能不命中而双层命中，去重不能把两层当成同一个变体；目标文件不存在时返回 200 首页，不能仅凭状态码判命中，必须比对内容特征。

硬约束：并发 send 按目标串行，同一长度的基线只能被请求一次，重复请求数为零；快照恢复后基线与已探测变体可往返，同一目标上基线与变体的计数互不影响，多次调用的合计按调用累加。

Variant 含 layer、raw、key，Response 含 status、body，ProbeRecord 含 layer、raw、key、baseline_status、baseline_length、baseline_body、variant_status、variant_body，Verdict 含 key、layer、hit、reason。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。交付改好的源码与自测输出，说明每处改动的触发条件。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: path_traversal_prober
- typeName: PathTraversalProber

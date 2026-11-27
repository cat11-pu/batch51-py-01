# batch51-py-safety-b-08

## 题面

边缘转发器升级后，上游报来两类问题：一类带路由头的报文整段消失，抓包在转发侧就断了，日志里只写了一个总数；另一类带两个目的选项头的报文，前半段选项被保留、后半段被合并处理，上层解析到的选项列表和发送方写的完全对不上。还有人反馈逐跳选项不允许的链路里，带该头的报文没有被丢弃，而是被截短后继续转发，审计里查不到对应包号。范围是 gsb/batch51-py-safety-b-08 的 ipv6_ext_header_filter.py，类 ExtHeaderFilter，负责扩展头链解析、裁决、剥离、按来源取策略与快照恢复，无法处理的输入抛 ExtHeaderError(code, detail)。

公开接口：ExtHeaderFilter(*, max_chain_length=256, max_headers=8, audit_limit=64)；register_interface(iface, policy=None)、remove_interface(iface)、policy_for(iface)、parse_chain(raw)、evaluate(packet, iface=None)、strip(packet, iface=None)，另有 verdict_for、audit_trail、stats、snapshot、restore。packet 含 packet_id、source、headers，每个头含 kind、length、options，路由头再带 routing_type。

故障与边界：①策略按接口登记，options 去重升序、routing_types 升序保存，未登记接口取内置默认策略，policy_for 返回可随意修改的副本，remove_interface 对未知接口返回 False；②parse_chain 按出现顺序编号，kind 或 length 缺失、raw 不是列表报 EXT_INVALID_PACKET；③链路合法时裁决为 forward、reason 为 ok、header_index 为 None，chain_length 等于各头 length 之和；④策略不允许逐跳选项且未要求剥离时整包丢弃，reason 为 hop_not_allowed，header_index 指向该头；⑤策略要求剥离时裁决为 strip、reason 为 hop_stripped，strip 返回去掉该头之后的剩余头，headers_removed 按实际摘除条数累计；⑥逐跳选项不在白名单内丢弃，reason 为 hop_option_denied；目的选项不在白名单内丢弃，reason 为 dest_option_denied；⑦路由头类型先在白名单内判定，不在白名单内丢弃并记 routing_type_denied，类型 0 与类型 4 一律丢弃并单独记 routing_type_reserved，未知类型按丢弃处理；⑧分片头之后再出现逐跳选项丢弃并记 hop_after_fragment，ESP 头之后还有任何扩展头丢弃并记 esp_not_last；⑨同一报文出现两个目的选项头时只有第一个允许保留，第二个出现即丢弃并记 duplicate_dest，不做合并；⑩扩展头链总长超过 max_chain_length 整包丢弃并记 chain_too_long，不得截断后交给上层，头个数超过 max_headers 丢弃并记 too_many_headers；⑪audit_trail 按发生顺序返回最近 audit_limit 条裁决，limit 参数只截取尾部，verdict_for 取该包号最近一次裁决，未知包号返回 None；⑫stats 返回 forwarded、stripped、dropped、headers_removed、policy_updates。

硬约束：更新接口策略与在途报文裁决并发时，单条报文只能看到完整的旧策略或完整的新策略，不得出现半新半旧的判定；审计与计数随裁决原子写入，不能出现有条目无计数。快照固定 version、policies、audit、stats 四键，深拷贝，restore 校验结构与版本，缺键或类型不符报 EXT_SNAPSHOT_INVALID 且原状态不动，恢复后策略、审计尾部与计数继续可用，重启不丢最近裁决。

验收：python3 -m pytest -q tests 15 条全过；不改测试、不跳过、不按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- module: ipv6_ext_header_filter
- typeName: ExtHeaderFilter
- file: ipv6_ext_header_filter.py

# batch51-py-safety-b-09

## 题面

财务共享盘的客户端升级后，两个部门陆续报障：域策略明明要求签名，但只开旧方言的客户端协商照样成功，会话落成不签名，后续消息全是明文；另有几台机器在心跳包上签名校验失败却被放过，直到断开树时才把问题暴露出来；运维按客户端复盘时只看到一条总数，分不清是能力不足还是方言不匹配。安全基线要求签名在协商阶段就定下来，事后再补没有意义，因此每一条协商拒绝和校验失败都要能落到具体客户端。范围是 gsb/batch51-py-safety-b-09 的 smb_signing_guard.py，类 SmbSigningGuard，负责协商、签名要求裁决、消息校验、会话密钥、拒绝记录与快照恢复，拒绝一律抛 SmbError(code, detail)。

公开接口：SmbSigningGuard(*, server_dialects=("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"), require_signing=True, allow_encryption=True, preauth_required=True, max_sessions=32)；negotiate(client_id, dialects, capabilities=(), now=None)、open_session(client_id, session_id, now=None)、close_session(session_id, reason=None)、sign(session_id, message)、verify(session_id, message, signature, now=None)，另有 negotiation_for、session_state、session_key、preauth_update、preauth_hash、verify_preauth、failure_log、stats、snapshot、restore。

故障与边界：①方言取服务端与客户端交集里版本最高者，交集为空报 SMB_DIALECT_UNSUPPORTED，客户端方言列表去重升序放进 dialects；②require_signing 为真而客户端能力里没有 signing 报 SMB_SIGNING_UNAVAILABLE，不能降级成无签名会话，客户端只报旧版方言时同样按方言不支持拒绝，不得回退；③客户端同时声明加密与签名时 signing_required 与 encryption_required 都为真，签名不会被加密替代；④同一客户端重复协商报 SMB_NEGOTIATION_DUPLICATE，首次结果保留；⑤open_session 要求该客户端已协商，未协商报 SMB_NOT_NEGOTIATED，session_id 重复报 SMB_SESSION_EXISTS，活动会话数达到 max_sessions 报 SMB_SESSION_LIMIT；⑥会话密钥按会话隔离，长度 32 位十六进制，两个会话密钥不同，session_state 返回 active、closed、unknown；⑦sign 与 verify 用会话密钥计算，签名 64 位十六进制，校验通过返回 True 并让 signatures 加一；⑧签名不符报 SMB_SIGNATURE_INVALID 并计入失败，同一会话校验失败一次即终止会话，心跳与断开树请求不例外；⑨拿另一会话的签名去校验同样按不符处理，不得跨会话复用密钥；⑩close_session 首次返回 True，重复返回 False，已关闭会话再做校验报 SMB_SESSION_CLOSED；⑪预认证按连接累积消息哈希，preauth_update 返回当前哈希，verify_preauth 与期望值不符返回 False 并计 preauth_mismatches，不抛异常；⑫协商响应声明的签名要求与实际校验不一致时以服务端策略为准并记录一次配置漂移，failure_log 按客户端返回 (client_id, 原因) 顺序元组。

硬约束：并发建立多个会话时签名密钥按会话隔离，密钥表不得串号，协商与校验共用的状态不能出现半写入；快照固定 version、negotiations、sessions、keys、preauth、stats 六键，深拷贝，restore 校验结构与版本，缺键或类型不符报 SMB_SNAPSHOT_INVALID 且原状态不动，恢复后活动会话仍能通过签名校验，重启不丢已建立的会话密钥。stats 返回 negotiated、refused、sessions、signatures、signature_failures、preauth_updates、preauth_mismatches。

验收：python3 -m pytest -q tests 15 条全过；不改测试、不跳过、不按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- module: smb_signing_guard
- typeName: SmbSigningGuard
- file: smb_signing_guard.py

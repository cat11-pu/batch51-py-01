# batch51-py-safety-b-18

## 题面

跨站联邦互通上线后，社区运营发现同一条转发被计入两次热度，拉黑某个实例后它的活动仍能通过别人的转发链进来；更糟的是一次转发把原帖 body 重新序列化后签名对不上，对端直接返回 401，用户看到的是转不出去的报错。运营手工补发的转发有的成功有的失败，热度榜反复重排，同一个 actor 的密钥在轮换当天还能用、第二天就全挂，值班只能把整个实例从联邦名单里摘掉。范围是 gsb/batch51-py-safety-b-18 的 activitypub_inbox_guard.py，类型 ActivityPubInboxGuard，负责校验联邦收件箱请求并处理活动。

公开接口：register_actor(actor_id, inbox, *, secret, key_id=None, now=0)；rotate_key(actor_id, secret, *, key_id=None, now=0, grace=300)；delete_actor(actor_id)；block_actor(actor_id)；unblock_actor(actor_id)；actor_state(actor_id)；fetch_actor_key(actor_id, *, key_id=None, now=0)；verify_signature(request, *, now)；ingest_activity(request, *, now)；dedupe(activity_id)；delivery_status(activity_id)；forward(activity_id, *, target_inbox, depth, now=0)；inbox_depth(inbox)；snapshot()；restore(state)；stats()。拒绝时统一抛 FederationError(code, detail)。

签名口径：请求头必须覆盖 request-target、host、date、digest 四项；digest 为 "sha256=" 加 body 的 sha256 十六进制；签名值为 sha256(secret + "|" + target + "|" + host + "|" + date + "|" + digest) 的十六进制小写，字段按这个顺序拼接；date 与当前时间相差超过 300 秒拒绝。

要修的故障与边界：①actor 的 id、inbox、密钥任一为空抛 FED_INVALID_REQUEST，重复注册抛 FED_ACTOR_EXISTS；②缺覆盖字段抛 FED_SIGNATURE_HEADERS，detail 里 missing 给出缺失头名列表；③date 越窗抛 FED_DATE_SKEW；④digest 与 body 不符抛 FED_DIGEST_MISMATCH；⑤签名不符抛 FED_SIGNATURE_INVALID；⑥keyId 必须属于该 actor 且未过期，否则按情况抛 FED_ACTOR_UNKNOWN、FED_KEY_MISMATCH 或 FED_KEY_EXPIRED；⑦同一 activity id 只处理一次，重复投递返回 duplicate，不重复计入收件箱；⑧拉黑 actor 后其活动一律拒绝；⑨去重表有窗口上限，超出淘汰最旧；⑩转发链深度超过上限丢弃，detail 带 depth；⑪收件箱容量满时拒绝，未处理过的活动 id 的 delivery_status 返回 unknown；⑫密钥轮换后旧签名在宽限期内仍可用，宽限期按 rotate_key 传入的 grace 与 now 计算，未指定 key_id 时生成的 key 必须与已有 key 不同；⑬同一活动从不同收件箱重复到达只处理一次，但每个收件箱的投递确认都要回；⑭actor 删除后其历史活动的转发链仍可能到达，按删除墓碑拒绝，不得重新拉取密钥；⑮转发必须原样带原始 body 与原始签名，重新序列化会破坏 digest。

硬约束：并发 ingest 按 activity id 串行，同一 id 只能有一次 delivered，其余全部 duplicate，读到的活动状态不能是处理中的中间态；快照保存 actor 密钥、去重表、收件箱水位与投递计数，restore 后重复活动仍判 duplicate，去重表、收件箱水位和密钥版本必须一起恢复，缺任何一项都会让已经处理过的活动在重启后被再算一次热度，非法快照整份拒绝且不污染现有状态；去重窗口与收件箱容量都是硬上限，不得静默淘汰已投递记录。stats 至少返回 delivered、duplicates、rejected、forwarded 四个计数。

验收：python3 -m pytest -q tests 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发收件与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: activitypub_inbox_guard
- typeName: ActivityPubInboxGuard

# batch51-py-safety-a-13

## 题面

密钥轮换平台这周出了两起事故：一次是某个服务主体的同一轮换请求被重试了三遍，台账里冒出三个版本，副本各自装了不同版本；另一次是轮换没走完就把新版本发给了客户端，回滚后台账版本号却倒着走。冷备节点恢复台账后还得接着往上编号，不能因为一次恢复动作把旧版本重新发一遍。范围是 gsb/batch51-py-safety-a-13 的 keytab_rotation_ledger.py，类 KeytabRotationLedger，维护各服务主体的密钥版本、副本分发状态与保留期。

公开接口：KeytabRotationLedger(*, retention=3600, clock=None)；register_principal(*, principal, replicas)；rotate(*, principal, request_id=None, now=None)；distribute(*, principal, version, now=None)；confirm(*, principal, version, replica_id, ok=True, now=None)；retire(*, principal, version=None, now=None)；active_version(principal)；issuable_versions(principal)；verifiable_versions(principal)；snapshot()；restore(state)；stats()。时间用秒级 ISO 8601 字符串。拒绝抛 KeytabError(code, detail)，错误码统一为 KEYTAB_ 前缀，取值包括 REQUEST_INVALID、PRINCIPAL_EXISTS、PRINCIPAL_UNKNOWN、ROTATION_IN_FLIGHT、VERSION_UNKNOWN、STATE_INVALID、NOT_DISTRIBUTED、REPLICA_UNKNOWN、ACTIVE_RETIRE、SNAPSHOT_INVALID。rotate 与 confirm 返回 KeyVersion(principal、version、state、request_id、replicas、created_at、retained_at)，state 取 distributing、distributed、active、retained、aborted；副本行为 ReplicaState(replica_id、status)，status 取 pending、distributed、confirmed、failed；distribute 返回按副本标识升序的副本行。

要修的行为：① 登记主体时副本列表必须非空且不重复，重复登记同一主体拒绝，未登记主体不能轮换；② 轮换生成的版本号按主体单调递增、从 1 起，即使中途作废也不得复用；③ 同一主体已有未完成轮换时新的轮换拒绝，除非携带的 request_id 与在途请求相同；④ 携带相同 request_id 的重复轮换返回同一版本内容，版本计数只加一次，幂等命中单独计数；⑤ 分发只对处于分发中的版本生效，重复分发按状态非法拒绝，分发后各副本状态为已分发；⑥ 未分发就确认按未分发拒绝，未知副本按副本不存在拒绝；⑦ 全部副本确认成功后版本转为生效，旧生效版本转为保留并记录保留起始时间；⑧ 保留期按保留起始时间加保留秒数计算，到点整即视为到期；⑨ retire 不带版本时清理到期保留版本并返回条数，指定版本时只清理该版本；⑩ 生效版本不允许 retire，分发中的版本也不允许，未知版本按版本不存在拒绝；⑪ 部分副本确认失败时新版本不得对客户端生效，回滚回到轮换前版本且版本号不回退；⑫ 保留期内的旧版本在副本缺新版本时仍可验签，但不得用于签发；只有生效版本可签发，可验签集合由生效与保留版本组成。

硬约束：同一主体同一 request_id 被并发轮换时只产生一个版本，其余请求返回同一版本号；轮换过程中的中间态必须可恢复，任何一步失败都不能出现两个同时生效的版本；快照深拷贝，恢复后轮换编号不得回退、副本确认状态与保留期都不丢，非法结构整体拒绝；版本号单调与保留期边界都是硬约束。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-a-13
- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: keytab_rotation_ledger
- typeName: KeytabRotationLedger

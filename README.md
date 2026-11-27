# batch51-py-game-a-11

## 题面

登录服这周连着出状况：安卓某渠道的玩家把客户端升到 1.10.0 之后反而被挡在门外，1.9.9 却能进；带 -rc 后缀的预发布包被当成低版本；还有账号反馈自己在灰度名单里，早上能进晚上又被踢回登录界面。范围是 gsb/batch51-py-game-a-11 的 client_version_gate.py，类 ClientVersionGate，负责按平台与渠道判定客户端能否接入、协商协议版本并维护灰度放行。

公开接口：ClientVersionGate(*, max_history=200)；set_policy(platform, channel, *, min_version, recommended_version=None, protocol_min=1, protocol_max=1, allow_prerelease=False) 返回策略版本号；drop_policy(platform, channel)；policy_of(platform, channel) 返回 VersionPolicy；admit(account, *, platform, channel, client_version, protocol_version, now=None) 返回 Admission；negotiate(account, *, platform, channel, client_version, protocol_versions, now=None) 返回 Negotiation；grant_gray(account, platform, channel)、revoke_gray(account, platform, channel)、gray_bucket(account, client_version)、reason_of(account)、history_of(account)；snapshot、restore、stats。拒绝抛 GateError(code, detail)。

要修的行为：①版本比较按数字段逐段进行，缺省段按 0 补齐，1.10.0 必须高于 1.9.9，不能按字符串字典序；②账号、平台、渠道为空串或只含空白、协议版本小于 1 时一律报 GATE_INVALID_REQUEST，版本串只接受两到三段数字加可选的 -rc.1 这类后缀，其他形态报 GATE_INVALID_VERSION，且都不写历史、不涨计数；③策略按平台与渠道分别维护，每次写入都让版本号加一，recommended_version 不传时与最低版本相同，协议区间下界不得大于上界，下线不存在的策略报 GATE_UNKNOWN_POLICY；④低于最低版本返回 BELOW_MIN_VERSION，协议版本落在协议区间之外返回 PROTOCOL_MISMATCH，两者都不放行，判定结果必须带命中策略的版本号；⑤预发布客户端的最低版本判定只看主三段，是否接收由 allow_prerelease 决定，后缀里的预发布号参与灰度分桶；⑥平台与渠道组合没有对应策略时按未知渠道拒绝，不能回退到任何全局默认放行；⑦灰度名单内的账号低于最低版本也能进，reason 记 GRAY_PASS 且 gray 为真，但不得改动策略里的最低版本；⑧灰度只放宽版本，不绕过协议区间；⑨灰度资格绑定授予时的策略版本，策略被重写或下线后立即失效，已经结束的判定记录不追溯改写；⑩negotiate 从客户端上报的协议列表里选出服务端区间内的最大值，没有交集时 accepted_protocol 为空并返回 PROTOCOL_MISMATCH；⑪同一账号重复授予或撤销灰度按幂等处理，返回真值表示状态真的发生变化；⑫history_of 只保留最近 max_history 条判定并按发生顺序升序，记录带账号、版本串、平台、渠道、命中的策略版本与判定时刻，reason_of 返回最后一条的 reason。

硬约束：策略写入与准入判定并发时，返回的策略版本号必须与判定实际使用的规则一致，不能读到半套策略；快照整体替换，结构必须包含 version、policies、gray、history、stats 五个键，结构不符报 GATE_SNAPSHOT_INVALID 且不影响在跑的判定；每账号历史有硬顶，不能无限增长。stats 返回 policies、policy_updates、admissions、allowed、rejected、gray_grants、gray_active。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: client_version_gate
- typeName: ClientVersionGate

# batch51-py-safety-b-01

## 题面

分支机房的 OSPF 邻居这两天很不稳：两台设备互相看见对方、状态却一直停在初始，退出重进后邻居表又是空的；链路状态库重启后条目全部丢失，同一条外部路由反复刷新把表项越堆越大，最后连管理口的会话都被拖慢。运维怀疑是 Hello 参数校验和链路状态装载的顺序出了问题，但把配置回滚到上周版本后现象依旧。需要整改的是 gsb/batch51-py-safety-b-01 下的 ospf_adjacency_guard.py，类型 OspfAdjacencyGuard，按 (路由器标识, 接口) 维护邻居状态机，按 (LSA 类型, 链路状态标识, 通告路由器) 维护链路状态库，拒绝的请求抛 OspfError(code, detail)，调用方按 code 分支处理，不依赖异常文本。

公开接口：OspfAdjacencyGuard(*, router_id="10.0.0.1", max_lsa=128, clock=None)；configure_interface(iface, area_id, hello_interval=10, dead_interval=40, auth_type=0, auth_data="")；process_hello(iface, hello, now=None)；verify_auth(iface, hello, now=None)；accept_db_description(router_id, iface, dbd, now=None)；load_lsa(lsa, now=None)；lookup_lsa(lsa_type, link_state_id, adv_router)；lsdb()；age_tick(now=None)；flush_max_age(now=None)；overflow_state()；snapshot()；restore(state)；stats()。

故障与边界：①接口未配置或参数非法（空接口名、负序列号、未知 LSA 类型、空链路状态标识）抛 OSPF_INVALID_ARGUMENT，失败不得留下半条记录；②Hello 的 hello/dead 间隔与接口配置不一致抛 OSPF_HELLO_MISMATCH，且不得建立邻居；③认证类型或口令不符抛 OSPF_AUTH_FAILED，计入 auth_failures，邻居表保持不变；④同一 (路由器标识, 接口) 只保留一条邻居，重复 Hello 仅把 dead_at 推到 now+dead_interval，不新增行；⑤邻居死区到期由 age_tick 转 down 并计数，之后收到 Hello 回到 init；⑥LSA 序列号更大才替换并计 refreshed，更小返回 stale 且原条目与接收时间都不动；⑦序列号相同、校验和也相同返回 duplicate，不刷新接收时间，也不重复计 loaded；⑧条目有效年龄（接收时年龄加驻留时长）达到 3600 秒时 age_tick 标记 MaxAge 并返回新增标记数，flush_max_age 才真正删除并计 flushed；⑨快照键固定为 version、neighbors、lsdb、maxage、overflow、stats，非法结构抛 OSPF_SNAPSHOT_INVALID 且原状态不变；⑩两个实例序列号相同但校验和不同时必须视为不同实例并保留先到者，返回 conflict 并计数，不能因为序列号一致就当成重复丢掉；⑪邻居进入交换阶段后收到区域号不匹配的数据库描述报文要退回 init，而不是直接判为失效或清空邻居；⑫链路状态库达到上限时新增外部 LSA 要拒绝并置溢出标志，已存在的内部 LSA 刷新不受影响，溢出后 overflow_state 返回 True 直到容量回落。

硬约束：同一 LSA 的多份实例并发到达时，锁内只允许保留序列号最大的那一份，最终库里每个三元组只有一条，统计计数要与实际结果对得上，相邻两次读取之间不得出现负值；快照必须深拷贝，恢复后邻居、条目、MaxAge 标记、溢出标志与计数一致，且不得把已老化条目重新放回；LSDB 上限是硬顶，任何路径都不能越过。stats 返回 hellos、neighbors_down、lsa_loaded、lsa_refreshed、lsa_stale、lsa_duplicate、lsa_conflict、lsa_maxage、lsa_flushed、auth_failures。

验收：python3 -m pytest -q tests 15 条用例全过；不得改测试、跳过用例或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: ospf_adjacency_guard
- typeName: OspfAdjacencyGuard

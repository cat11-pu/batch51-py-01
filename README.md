# batch51-py-safety-c-12

## 题面

本地凭据校验网关上线后出现两类事故：一次是客户端在连接建立后切换了用户身份，网关在后续请求里又按新身份判了一遍，把本该拒绝的请求放了过去，事后审计只能看到两条互相矛盾的结果；另一次是容器里的对端进程在宿主机命名空间外看不到，网关只比了用户号就放行，外部同名用户直接拿到了租户数据。排障时还发现同一连接上后续追加传递的凭据会覆盖先前判定，连接身份来回跳，同一个连接在十秒内被记成三个不同用户。请修 gsb/batch51-py-safety-c-12 下的 unix_peer_cred_gate.py，类 UnixPeerCredGate，负责连接建立瞬间的凭据固化、命名空间对照与内外标识映射。

对外接口：UnixPeerCredGate(*, max_connections=16)；register_tenant(tenant, *, uids, user_ns, pid_ns, processes=())；tenant_config(tenant)；accept_connection(connection_id, *, pid, uid, gid=0, start_time, user_ns, pid_ns)；snapshot_cred(connection_id)；append_cred(connection_id, *, pid, uid, start_time, gid=0, user_ns="", pid_ns="")；add_id_mapping(*, pid_ns, inner_pid, outer_pid)；map_ids(*, pid_ns, outer_pid)；verify_peer(connection_id, *, tenant)；close_connection(connection_id)；open_connections()；snapshot()；restore(state)；stats()。拒绝时抛 PeerCredError(code, detail)。判定状态取 allowed、rejected、unverifiable 三种，判定结果包含 status、reason、credential、mapped_pid 四个字段，冻结凭据包含 connection_id、pid、uid、gid、start_time、user_ns、pid_ns 七个字段；stats 返回 accepted、closed、allowed、rejected、unverifiable、refused 六个计数，allowed、rejected、unverifiable 按每次判定结果累计，refused 按每次被拒操作累计；snapshot 返回 version、tenants、connections、mappings、stats 五个键。open_connections 返回升序连接号元组，snapshot_cred 对未知连接返回 None，tenant_config 对未知租户返回 None。

要修的点：①租户允许的用户号去重升序，允许进程身份按 pid 与启动时间升序，重复注册报 PEER_TENANT_EXISTS；②空租户、空用户集合、负用户号、空命名空间、非法进程身份报 PEER_INVALID_REQUEST；③连接号重复报 PEER_CONNECTION_EXISTS，超过上限报 PEER_CAPACITY_EXCEEDED；④pid、uid、gid、启动时间与两个命名空间任一非法即拒绝，不写入半条连接；⑤连接建立时把凭据整份固化，之后查询与判定只用冻结副本；⑥判定顺序为用户号、用户命名空间、进程命名空间、进程启动时间，全部命中返回 allowed 与理由 PEER_TRUSTED 并带出映射后的内层 pid，分别失败则给出 PEER_UID_MISMATCH、PEER_USER_NS_MISMATCH、PEER_PID_NS_MISMATCH、PEER_PROCESS_MISMATCH，同一 pid 换了启动时间必须按进程复用拒绝；⑦未知连接 PEER_UNKNOWN_CONNECTION，未知租户 PEER_UNKNOWN_TENANT，关闭后的连接 PEER_CONNECTION_CLOSED，关闭幂等且冻结凭据仍可审计查询；⑧映射按命名空间隔离，同一外层号映射到不同内层号报 PEER_MAPPING_CONFLICT，重复相同映射幂等；⑨同一连接上追加传递的凭据只进审计，不得改写已固化的连接身份；⑩内外标识映射缺失时判定为不可验证 PEER_ID_UNMAPPED，不得退化成只比用户号就放行；⑪快照深拷贝，restore 校验租户、连接、映射与统计结构，非法报 PEER_SNAPSHOT_INVALID 且原状态不变；⑫统计要能分辨通过、拒绝与不可验证三种判定结果，未知连接与未知租户也各有计数。

硬约束：并发接入必须持锁，连接号不得重复发放，容量上限不得被击穿，统计不得丢更新；快照恢复后冻结凭据、租户规则、映射与关闭标记都要还原，重启不得重新读取对端当前身份，已判定的连接在恢复后结果不变；判定结果一旦产出即固化，同一连接重复校验结果稳定，数据库里的历史结论不得被后续请求改写。租户规则在网关启动时一次装载，运行期不允许因单条连接校验失败而回退到默认放行。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或用固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: unix_peer_cred_gate
- typeName: UnixPeerCredGate

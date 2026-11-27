# batch51-py-safety-c-09

## 题面

同机上一个普通用户把自己的套接字路径换成别人的同名文件后，代理进程连到了错误的服务端；抽象命名空间里两个服务抢同一个名字，先起的那个被顶掉；进程退出后条目一直挂着，后来者注册同名反而被拒。更奇怪的是两个容器各自监听同一个抽象名，宿主机只能看到一条记录；有的连接建立之后客户端进程已经被替换，服务端还在按旧身份放行。范围是 gsb/batch51-py-safety-c-09 的 unix_socket_guard.py，类 UnixSocketGuard，负责本机套接字注册、绑定、对端授权与租约回收。

公开接口：UnixSocketGuard(*, lease_ttl=60, max_bindings=128)；register(binding_id, *, namespace, owner_uid, owner_pid, mode=0o600, dir_mode=0o755, abstract=None, path=None, now)；bind(binding_id, *, now)；authorize(binding_id, peer, *, now)；connect(binding_id, peer, *, now)；verify(conn_id, current)；release(binding_id)；heartbeat(binding_id, *, now)；expire(now)；lookup(namespace, name)；bindings()；connections()；snapshot()；restore(state)；stats()。peer 与 current 是 PeerCred(pid, uid, gid, exe)；拒绝抛 SocketError(code, detail)。

要修的行为：①注册时抽象名与路径二选一，都给或都为空报 SOCKET_INVALID_REQUEST，路径必须是绝对路径；②命名空间与承载者标识不能为空，属主 uid 不得为负；③模式位除属主外还带组或其他权限时报 SOCKET_MODE_INSECURE；④路径套接字父目录允许他人写入时必须拒绝绑定并报 SOCKET_DIR_INSECURE，文件自身权限正确也不足以放行；⑤同一命名空间内同名活动条目重复注册报 SOCKET_NAME_TAKEN，已释放或过期的名字可以复用；⑥绑定后按 lease_ttl 生成租约，重复绑定报 SOCKET_ALREADY_BOUND，未注册条目报 SOCKET_BINDING_UNKNOWN；⑦授权要求条目已绑定且租约未过期，否则分别报 NOT_BOUND 与 LEASE_EXPIRED；⑧对端 uid 等于属主或为 0 才放行，其余报 PEER_NOT_PERMITTED；⑨抽象套接字名在不同网络命名空间里可以重名，命名空间标识必须进入注册键，同名条目在不同命名空间各自独立计数；⑩对端凭据在连接时有效但随后进程被替换，已建立的连接要按会话结束处理而不是继续信任；⑪heartbeat 刷新租约，expire 回收到期条目并结束其连接，返回回收条数，回收后名字可立即被重新注册，绑定成功返回带租约的条目，lookup 与 bindings 只返回活动条目；⑫快照为 dict 深拷贝，含 version、bindings、connections、counters，counters 为 dict，调用方就地清空或改写任一表都不得影响运行中的状态，缺字段或类型不对报 SOCKET_SNAPSHOT_INVALID 且不动现存状态，连接记录要保留对端凭据与建立时刻。authorize 返回 Decision(status、code、binding_id、peer_uid)；条目记录绑定编号、命名空间、类型、名字、属主、模式、状态、绑定时刻与到期时刻，状态取 registered、bound、released、expired；verify 只返回 open、ended、unknown 三者之一；stats 返回 registered、binds、connections、allowed、denied、released、expired、ended 八项。

硬性约束：并发绑定同一条目只能有一个成功，其余看到 SOCKET_ALREADY_BOUND，不能出现两个持有者；进程重启后凭快照还原注册表、租约与连接状态，过期条目不得借恢复复活，恢复失败不能覆盖现有注册表；注册条目数、每命名空间条目数与连接数都设硬上限，同一命名空间的条目数单独封顶，超限报 SOCKET_CAPACITY_EXCEEDED，不得静默淘汰已有条目。

验收：python3 -m pytest -q tests 跑满 15 条用例全过；测试不许改、不许跳过、不许按固定输入写死；并发绑定与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: unix_socket_guard
- typeName: UnixSocketGuard

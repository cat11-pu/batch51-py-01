# batch51-py-safety-c-11

## 题面

线上终端网关这周连续报障：一套租户环境里两个互不相干的运维会话被分到了同一个伪终端号，键盘输入串到对方窗口，值班同事只能手工重启网关把号池清空；另有客户反映重启后原本占着号的会话还在跑，新会话却被分到同一个号，两边的读取进程互相抢字符，日志里同时出现两份终端回显。更糟的是配额面板上的数字和实际持有量对不上，已释放的号还占着额度，整池号被单个租户卡死，其他租户排队半小时也拿不到终端。请修 gsb/batch51-py-safety-c-11 下的 pty_session_allocator.py，类 PtySessionAllocator，维护终端号池、会话首领绑定与租户归属。

对外接口：PtySessionAllocator(*, devices=("pts/0", "pts/1", "pts/2", "pts/3"), max_per_tenant=4)；add_device(device_id)；allocate(tenant, *, device_id=None, now=None)；bind_session(device_id, *, session_id, leader_pid, leader_start, now=None)；hold(device_id, *, pid, start, role="child")；release(device_id, *, now=None)；flush_release(device_id, *, alive=None)；reclaim_orphans(*, alive, now=None)；usage(tenant)；lookup(device_id)；records_for(tenant)；snapshot()；restore(state)；stats()。拒绝时抛 PtyError(code, detail)。设备状态取 free、allocated、bound、releasing 四种，设备记录包含 device_id、tenant、session_id、leader_pid、leader_start、state、generation 七个字段；stats 返回 allocations、bindings、releases、flushed、reclaimed、refused 六个计数，其中 allocations 只在空闲号租出时加一，releases 只在进入释放中时加一；snapshot 返回 version、devices、stats、max_per_tenant 四个键。lookup 对未知设备号返回 None，records_for 返回升序元组，usage 对未知租户返回 0。

要修的点：①号池只接受 pts/<数字> 形式的设备号，非法号与重复加号分别报 PTY_INVALID_REQUEST 和 PTY_DEVICE_EXISTS，不得留下半条记录；②分配取编号最小的空闲号，池空报 PTY_POOL_EXHAUSTED；③租户未释放数量达到上限报 PTY_TENANT_QUOTA，已标记释放的号不计入配额；④指定号被其他租户占用报 PTY_DEVICE_BUSY，未知号报 PTY_DEVICE_UNKNOWN；⑤同一租户重复申请自己已持有的号返回原记录，不重复计入配额；⑥绑定时号必须处于已分配状态，重复绑定报 PTY_STATE_INVALID，同一 session_id 不能落在两个号上，否则 PTY_SESSION_CONFLICT；⑦释放幂等，已释放再释放返回 False，释放中的号不能被重新分配；⑧flush_release 在首领仍存活时拒绝，只有首领退出后才归还号并递增代号；⑨reclaim_orphans 只回收首领已退出的号，返回升序设备号列表，持有从设备的残留进程仍存活时该号必须原样保留；⑩空租户、带首尾空白的租户、非法 pid 或启动时间、错误设备号一律 PTY_INVALID_REQUEST；⑪records_for 按设备号升序且只返回本租户；⑫快照深拷贝，restore 校验版本、设备字段、状态取值与统计键，非法结构报 PTY_SNAPSHOT_INVALID 且原状态不动。

硬约束：并发分配必须持锁，任意并发下同一个号不得发给两个租户，配额与统计不得丢更新；快照恢复到新实例后归属、会话首领、代号与计数必须还原，重启对账以首领进程的启动时间为准，编号与代号不得回退，不能把旧号发给仍未退出的会话；每租户硬顶与池容量都是硬上限，超限只能拒绝不能挤占，拒绝路径同样要计入统计，接口返回与异常码是运维脚本唯一的判断依据。号池里每个号只能有一个活跃会话，这条不变量在分配、绑定、释放、回收四条路径上都要成立。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或用固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: pty_session_allocator
- typeName: PtySessionAllocator

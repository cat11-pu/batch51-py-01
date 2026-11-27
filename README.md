# batch51-py-safety-d-01

## 题面

凌晨的存储值班连着遇到三件怪事：一台机器上已经挂载的镜像被人换成同名文件，业务没有报错，读到的却是另一份数据；另一台机器上镜像被截短后回环设备照样能打开，等到文件系统写出 I/O 错误才发现；还有一批 autoclear 设备在挂载还没卸载时就被回收，设备号转手分给了别的镜像，卸载进程直接把数据写进了新设备。事后核对发现，绑定只记了路径，后备文件的设备号、inode、修改时间和大小一个都没留下，分离也没有等持有者退出；同一份镜像按两个偏移各绑一次还被当成同一个设备，容量怎么都对不上；手动分离被挂载挡住以后没有延迟处理，重试又报出另一个错误。范围是 gsb/batch51-py-safety-d-01 的 loop_device_lifecycle_guard.py，类 LoopDeviceGuard，负责回环设备的绑定、打开、重配、分离与自动回收。

公开接口：LoopDeviceGuard(*, max_devices=64, max_bindings_per_file=4, autoclear_default=False)；observe_file(path, *, dev, inode, mtime_ns, size)；attach(path, *, offset=0, sizelimit=None, read_only=False, autoclear=None)；detach(loop, *, holder=None)；reconfigure(loop, *, offset=None, sizelimit=None, read_only=None)；reclaim(*, now=0)；status(loop)；open_device(loop, *, holder)；close_device(loop, *, holder)；holders(loop)；bindings_for(path)；record_partitions(loop, partitions)；scan_partitions(loop)；snapshot、restore、stats。拒绝统一抛 LoopError(code, detail)。

要修的行为与边界：①attach 从最近一次 observe_file 读取签名，没有观测记录抛 LOOP_BACKING_UNKNOWN，detail 带 path，绑定记录的 generation 从 1 起；②偏移与长度必须落在文件内，offset 非负、sizelimit 为正且 offset 加 sizelimit 不超过文件大小，否则 LOOP_RANGE_INVALID，detail 带 offset、size_limit、size；③重复绑定只在 dev、inode、offset 与 size 全部相同时去重，两侧都只读复用同一设备并计 reused，任一侧可写抛 LOOP_SHARED_CONFLICT，detail 带已有 loop；④设备总数与单文件绑定数设上限，超限分别抛 LOOP_DEVICE_EXHAUSTED（detail 带 max_devices）与 LOOP_BACKING_LIMIT（detail 带 path 与 limit）；⑤手动设备仍有持有者时 detach 抛 LOOP_HELD，detail 带 holders；⑥open_device 与 close_device 维护持有者集合，holders 按字典序返回，关闭未知持有者抛 LOOP_NOT_HELD，close_device 返回剩余数量；⑦重配在有持有者时先抛 LOOP_BUSY（detail 带 holders），通过后重新校验范围并把 generation 加一；⑧分区扫描没有结果时为空元组，重配成功必须清空扫描结果，scan_partitions 每次调用累计 scans；⑨打开时后备文件的 dev 或 inode 变化按 LOOP_BACKING_DRIFT 拒绝，detail 的 reason 为 replaced，drift_refused 加一；仅修改时间变化放行并把 touched 置真；⑩reclaim 只回收没有持有者的 autoclear 设备并返回数量，设备号从 loop0 起单调分配，回收后旧号不再分给别的后备；⑪后备文件被截短后，下次 open_device 必须按大小漂移拒绝，不能等到真正读写才由底层 I/O 报错，drift_refused 同样累计；⑫autoclear 设备在仍有挂载持有者时分离要延迟到最后一个持有者关闭，延迟期间设备号不得再分配给其它后备，也不得让新的打开混进旧设备。

硬约束：并发 attach 与持有者变更用 RLock 串行，设备号不得重复发放；快照含 version、next_index、devices、observations、stats 五项，与现场深拷贝隔离，非法结构抛 LOOP_SNAPSHOT_INVALID 且不改现场；stats 返回 attaches、detaches、reclaimed、reused、drift_refused、touched、scans、restores 八项计数。

验收：python3 -m pytest -q tests 的 15 条全部通过，不得修改测试、跳过或按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: loop_device_lifecycle_guard
- typeName: LoopDeviceGuard

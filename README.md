# batch51-py-safety-b-06

## 题面

月初园区一条产线的网关把三台变频器的参数写乱了：操作员在监控页改一组频率，页面提示成功，设备侧只有前两个寄存器刷新，第三个还是旧值；链路抖动后客户端自动重试，本来只该写一次的点位被写了两遍；夜里值班的人想按设备回看这批被拒请求，只看到一串没有设备归属的计数。范围是 gsb/batch51-py-safety-b-06 的 modbus_write_guard.py，类 ModbusWriteGuard，负责写请求准入、寄存器区间隔离、请求转写、提交与回滚，拒绝一律抛 ModbusError(code, detail)。

公开接口：ModbusWriteGuard(*, max_registers_per_write=16, retry_window=8, max_devices=64)；register_device(device_id, *, slave_id, tenant, readable, writable, function_codes=(5, 6, 15, 16), now=None)、admit(request, now=None)、commit(request_id, now=None)、rollback(request_id, now=None)、translate(request_id)，另有 device_record、result_for、pending_for、device_values、exception_log、expire_results、stats、snapshot、restore。

故障与边界：①设备按 device_id 登记，可读区间和可写区间都是闭区间 (start, end)，start 大于 end 或为负报 MODBUS_DEVICE_INVALID，重复登记报 MODBUS_DEVICE_EXISTS，功能码白名单去重后升序保存，设备总数超过 max_devices 报 MODBUS_CAPACITY_EXCEEDED，device_record 对未登记设备返回 None；②request 缺字段、地址不是整数、count 小于 1 或 values 含非整数报 MODBUS_INVALID_REQUEST，统计不变；③未登记设备报 MODBUS_UNKNOWN_DEVICE；④写功能码不在白名单返回异常码 1，count 超单次上限、values 个数与 count 不等、值超 65535 都返回异常码 3；⑤准入通过时 registers 给出升序寄存器窗口，translate 输出 slave_id、function_code、address、count、values、exception_code 六键，values 保持元组顺序，pending_for 按 seq 升序返回未提交的请求号元组；⑥读功能码 1、2、3、4 不受写白名单限制，但读区间超出可读区间要按非法数据地址返回；⑦写多个寄存器时任一地址越权，整条请求拒绝，一个寄存器都不许写，不允许只生效一部分；⑧同一客户端在 retry_window 内提交完全相同的写请求，按幂等返回上次结果，不重写设备，也不计为越权；⑨commit 只对已准入且未提交的请求生效，重复提交报 MODBUS_REQUEST_COMMITTED，被拒请求报 MODBUS_REQUEST_DENIED，未登记请求报 MODBUS_UNKNOWN_REQUEST；⑩同一设备同一寄存器按 seq 定序，seq 小于该寄存器已提交序号的提交报 MODBUS_STALE_SEQUENCE 且不落值；⑪rollback 只回退本次写入，寄存器在本请求之后被更高 seq 写过时报 MODBUS_ROLLBACK_CONFLICT 且一个都不回退，成功回退后再次 rollback 返回 False，写前不存在的地址要删掉；⑫device_values 返回地址到值的字典副本，exception_log 按设备返回 (request_id, 异常码) 并按 seq 升序，expire_results 清理已终态且超出 retry_window 的准入记录并计数。

硬约束：同一客户端的准入、提交、回滚并发时按客户端串行，统计和寄存器值不得半更新；跨客户端并发写同一寄存器时仍按请求序号定序，旧序号不得覆盖新值；快照固定 version、devices、admissions、values、seq_marks、stats 六键，深拷贝，restore 校验结构与版本，缺键或类型不符报 MODBUS_SNAPSHOT_INVALID 且原状态不动，恢复后未提交的准入仍能 commit。stats 返回 admitted、denied、committed、rolled_back、registers_written、replayed、expired，rollback 不回退 registers_written。

验收：python3 -m pytest -q tests 15 条全过；不改测试、不跳过、不按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- module: modbus_write_guard
- typeName: ModbusWriteGuard
- file: modbus_write_guard.py

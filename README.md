# batch51-py-safety-c-08

## 题面

运维在关机时看到加密交换区被提前清钥，进程读到脏页后直接报数据校验错；另一次休眠恢复后系统起不来，交换区内容被写坏；还有人把同一把密钥同时挂到两块盘上，轮换时两块盘互相覆盖。现场还能看到关闭动作返回成功、进程随后仍读到旧页，重启后同一设备出现两套密钥记录。范围是 gsb/batch51-py-safety-c-08 的 swap_crypt_guard.py，类 SwapCryptGuard，负责加密交换区的启用、关闭、密钥轮换与休眠恢复参数。

公开接口：SwapCryptGuard(*, max_devices=8)；enable(device, *, size_pages, key_id, cipher, resume_offset, now)；disable(device, *, now)；mark_dirty(device, pages)；rotate_key(device, *, new_key_id, cipher=None, now)；resume(device, *, image_device, image_offset)；status(device)；devices()；pending_writeback()；recover()；snapshot()；restore(state)；stats()。拒绝抛 SwapError(code, detail)。

要修的行为：①设备标识、密钥标识、加密算法都不能为空，size_pages 必须为正，resume_offset 落在 0 到 size_pages-1，否则报 SWAP_INVALID_REQUEST；②同一设备同时只能有一套活动密钥，密钥已绑在另一台设备上时启用报 SWAP_KEY_CONFLICT；③关闭设备要等脏页回写完成后才清密钥，脏页未清零时只能停在 draining，密钥保留并计入延迟计数，等待期间不接受新的写入请求；④关闭后密钥、算法字段清空并计一次清零，已关闭设备再次关闭只回原状态不重复计数；⑤轮换密钥先停写再换钥，脏页未清时不得换，新密钥被别的设备占用同样报 SWAP_KEY_CONFLICT；⑥休眠恢复要求镜像设备与偏移和启用时登记的完全一致，不一致要失败并保留当前状态，不能写坏正在使用的交换区；⑦同一设备重复启用且参数完全一致要幂等返回已启用，参数不同则必须先关闭再启用；⑧设备数量超 max_devices 报 SWAP_CAPACITY_EXCEEDED，未知设备报 SWAP_DEVICE_UNKNOWN；⑨对未启用设备做恢复报 SWAP_NOT_ENABLED；⑩recover 把重启后残留的中间态收敛成已关闭，返回被清理的设备名，清理要计一次恢复；⑪stats 返回 enables、disables、rotations、resumes、idempotent、deferred、zeroized、recovered 八项；⑫快照为 dict 深拷贝，含 version、devices、counters，counters 为 dict，调用方就地清空或改写任一表都不得影响运行中的状态，缺字段或类型不对报 SWAP_SNAPSHOT_INVALID 且不动现存状态。设备清单按设备名升序返回，pending_writeback 只列出脏页大于零的设备，脏页清零后立即消失。generation 从 1 起，每次成功启用、关闭或轮换各加一，重复关闭与失败的调用不变；状态记录暴露 device、state、key_id、cipher、size_pages、resume_offset、generation、dirty_pages。

硬性约束：并发启停同一设备只能有一个生效，其余调用看到的是已经收敛后的状态，不能出现两次清零或两套密钥，同一设备的启停与轮换串行、跨设备之间仍可并行；进程重启后凭快照判定未完成操作并清理，已启用设备的密钥绑定、代次与脏页数要完整还原，恢复失败不能破坏当前设备；单设备脏页数、设备总数与恢复次数都设硬上限，超限报错不静默截断；密钥材料只登记标识与算法，不落明文。

验收：python3 -m pytest -q tests 跑满 15 条用例全过；测试不许改、不许跳过、不许按固定输入写死；并发启停与重启清理自行写程序验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: swap_crypt_guard
- typeName: SwapCryptGuard

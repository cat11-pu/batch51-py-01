# batch51-py-safety-d-04

## 题面

审计前翻日志目录，发现三个问题凑在了一起：一次轮转之后新文件的属主从服务账号变成了 root，进程再写就报权限拒绝；压缩失败留下的 .gz 半成品第二天被当成已经轮转，原始日志被下一次轮转直接覆盖；copytruncate 模式下写入方还握着旧句柄，截断之后的内容不知道该算哪一个文件，权限检查看的又是另一个。还有一台机器的日志目录被设成了 world-writable，新文件跟着放宽到谁都能写，配置里写的 su 指令从来没生效过。轮转任务原来只按文件名做检查，属主、模式和压缩结果都没有和新文件对齐，出了问题只能靠人肉逐台比对。范围是 gsb/batch51-py-safety-d-04 的 logrotate_permission_guard.py，类 LogrotatePermissionGuard，负责轮转计划、权限继承、压缩与校验。

公开接口：LogrotatePermissionGuard(*, umask=0o022, max_files_per_run=32, max_bytes_per_run=8388608, compress_mask=0o700)；register_logfile(path, *, owner, group, mode, rotation="create", su_user=None, su_group=None, world_writable_dir=False, immutable=False, symlink_target=None, size=1024, compress=True)；place_file(path, *, owner, group, mode, size=0)；stat(path)；stat_log(path)；generation(path)；archive_path(path, generation=None)；plan(paths)；rotate(path)；rotate_batch(paths)；compress(path, *, generation=None)；verify(path)；report()；snapshot、restore。拒绝统一抛 RotateError(code, detail)。

要修的行为与边界：①登记时校验绝对路径、owner 与 group 非空、mode 落在 0 到 0o7777、rotation 只取 create 与 copytruncate，否则抛 ROTATE_INVALID_REQUEST；plan 与 rotate 遇到未登记路径抛 ROTATE_UNKNOWN_FILE 并在 detail 带 path；②plan 不得改动任何文件，归档路径为“日志路径.下一代数”，新文件属主与属组取 su_user、su_group 覆盖后的值，模式默认沿用原模式，目录 world-writable 时按 umask 收紧，计划条目计入 planned；③符号链接目标一律拒绝而不是跟随，plan 与 rotate 都抛 ROTATE_SYMLINK_REFUSED，detail 带 path 与 target；④create 轮转给日志换新 inode 并把原内容留在归档里，新文件大小清零；copytruncate 保留 inode，同样把代次加一并归档原内容；⑤immutable 的文件按失败处理，抛 ROTATE_FAILED、detail 的 reason 为 immutable，原文件大小与代次都不动、不生成归档、failed 加一；⑥compress 把归档压成“日志路径.代次.gz”，模式收窄为原模式与 compress_mask 的交集，删除未压缩归档，日志代次不变，返回 archive、mode、owner 与 size；⑦verify 对当前日志比较属主与按收紧规则算出的模式，对压缩归档只判“不得比原文件更宽松”，发现码取 ROT_FILE_MISSING、ROT_SYMLINK、ROT_OWNER_MISMATCH、ROT_MODE_MISMATCH、ROT_PERM_LOOSER，每条发现是带 code 与 detail 的映射、detail 里的 path 指向涉事文件，report 汇总 rotated、compressed、refused、failed、planned 与 findings；⑧一次 plan 超过 max_files_per_run 或总字节超过 max_bytes_per_run 抛 ROTATE_CAPACITY（detail 带 limit），一个文件都不轮转；⑨原文件属主是非 root 服务账号时，create 模式新建文件必须沿用该属主，不能回落到 root；⑩压缩进程失败留下 .gz 半成品时，下一次轮转要识别并清理，不能当成已轮转；⑪copytruncate 期间写入方仍持有句柄，截断后新写入属于新文件，权限判定以新文件为准；⑫place_file 用于登记或覆盖归档、半成品等任意文件的属性，不改变已登记日志的轮转策略与代次。

硬约束：并发 rotate 按文件路径加锁串行，同一路径的代次必须连续，不得出现两个同代归档；快照含 version、files、logs、findings、counters 五项，与现场深拷贝隔离，非法结构抛 ROTATE_SNAPSHOT_INVALID 且不改现场。

验收：python3 -m pytest -q tests 的 15 条全部通过，不得修改测试、跳过或按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: logrotate_permission_guard
- typeName: LogrotatePermissionGuard

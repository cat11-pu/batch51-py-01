# batch51-py-safety-c-20

## 题面

运维的文件取证面板这两天连着报错：值班按挂载标识加文件句柄还原真实路径，明明在同一台机器上，A 容器的调用却能还原出 B 容器的目录，越权读到了别的租户的数据；有台机器的目录被改名之后，面板仍然显示旧路径，取证材料被质疑；还有一次文件删掉又重建，同名同 inode，面板直接命中缓存，把新文件的内容当成了旧证据提交。范围是 gsb/batch51-py-safety-c-20 下的 file_handle_resolver.py，类 FileHandleResolver，按调用方的挂载命名空间与权能解析句柄。

公开接口：FileHandleResolver(*, cache_size=16)；add_mount(mount_id, namespace, *, root="/")；remove_mount(mount_id)；enter_namespace(caller, namespace)；grant(caller, mount_id=None, *, path_prefix="/")；add_object(handle_id, *, mount_id, path, inode, generation=1, kind="file")；rename(handle_id, new_path)；unlink(handle_id)；recycle(handle_id, *, path, inode=None)；resolve(caller, handle_id)；authorize(caller, handle_id)；describe(handle_id)；invalidate(handle_id=None)；snapshot()；restore(state)；stats()。拒绝时抛 FhError(code, detail)。

要修的行为：① 挂载标识唯一，重复注册抛 FILEHANDLE_DUPLICATE_MOUNT；对象必须挂在已存在的挂载上，否则 FILEHANDLE_UNKNOWN_MOUNT；② 对象路径必须是绝对路径且落在挂载根目录之下，否则 FILEHANDLE_PATH_INVALID；同一挂载下同一路径重复登记抛 FILEHANDLE_DUPLICATE_PATH，句柄号重复抛 FILEHANDLE_DUPLICATE；③ 调用方先用 enter_namespace 声明所在命名空间，只能解析本命名空间内的挂载，跨命名空间一律抛 FILEHANDLE_MOUNT_HIDDEN；④ 没有匹配权能时 resolve 抛 FILEHANDLE_ACCESS_DENIED，authorize 只返回 False 不抛；权能按挂载加路径前缀匹配，前缀必须按路径分段对齐，"/srv/a" 不覆盖 "/srv/ab"；⑤ 解析结果带挂载标识、命名空间、路径、inode、生成号与类型，路径取解析时刻的值；⑥ rename 只改路径不换生成号并让旧缓存失效，unlink 把对象标记为已删除，describe 能看到 deleted，resolve 已删除对象抛 FILEHANDLE_STALE；⑦ 缓存按句柄号加生成号建键，容量由 cache_size 决定，超出按最久未用淘汰，命中计 cache_hits，未命中计 cache_misses；⑧ invalidate 传句柄号只清该句柄的缓存并返回清除条数，传 None 清空全部；未知句柄号的 resolve、describe、authorize 一律抛 FILEHANDLE_UNKNOWN；⑨ 目标在解析期间被改名到其他目录时返回解析时刻的真实路径，不得返回改名前的旧路径；⑩ 句柄删除后被重新复用时按生成号判为不同对象，缓存不得命中；⑪ 快照为 {"mounts": {...}, "callers": {...}, "objects": {...}, "stats": {...}}，必须深拷贝，结构不符抛 FILEHANDLE_SNAPSHOT_INVALID 且原状态一字不动；⑫ remove_mount 成功后该挂载上的对象不可再解析，返回是否真的移除。

stats 返回 resolves、authorized、denied、hidden、stale、cache_hits、cache_misses、evictions、invalidations 九个计数，缓存命中与淘汰都要如实累加。

硬约束：同一句柄并发解析与改名时，结果要么完整是旧路径要么完整是新路径，不得拼出半截路径，改名后缓存条目不得继续返回旧值；快照恢复后挂载、调用方命名空间、权能、对象与计数全部往返且不与入参共享内存。缓存容量是硬顶，任何路径都不能突破。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与缓存自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-c-20
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: file_handle_resolver
- typeName: FileHandleResolver

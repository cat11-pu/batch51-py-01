# batch51-py-safety-c-05

## 题面

文件服务这边上周被渗透测试点了一笔：一台对外提供挂载的机器上，测试同学从一台只被授权只读的网段主机拿到了可写挂载，理由是导出表里同一条路径给两个客户端写的选项被当成了一份合并后的结果；更早的一次是根用户压缩和全用户压缩被同时写进一行，挂载上去以后谁也没注意根用户其实没被压缩，一直按特权身份读写；还有一台机器的子目录已经从导出表里摘掉了，但早就挂着的客户端照样能读，直到重启才失效。运维说导出表是手写的，改完没有校验，也没有任何手段复现"当时生效的到底是哪一版"。

要做的是导出表治理守卫，落在 gsb/batch51-py-safety-c-05，文件名 nfs_export_guard.py，主类 NfsExportGuard，构造参数 source。导出表每行是路径加若干"客户端(选项,选项)"，选项按逗号分隔。对外接口：load_exports(text, *, source=None)、entries()、current_version()、match_export(path, client_ip)、specificity(entry, client_ip)、effective_options(path, client_ip)、authorize(*, path, client_ip, request="ro")、register_mount(*, client_ip, path)、verify_mount(*, client_ip, path)、mounts()、audit()、snapshot()、restore(state)、stats()；MountDecision 带 allowed、reason、path、client_ip、options、export_path、version。

要落实的边界：①空行与 # 注释跳过，路径必须是绝对路径，客户端只接受单个 IPv4、CIDR 与通配符，选项必须在已知集合内，任一不合规抛 NfsExportError，code 为 NFS_PARSE_FAILED，detail 带 line 与 message，旧表与旧版本号保持不动；②/proc、/sys、/dev 开头的伪文件系统路径不得导出，命中抛 NFS_PSEUDO_PATH，整张表拒绝加载；③同一路径多条导出按最长前缀取最具体者，路径前缀按分段比较，/srv/data 不能命中 /srv/database；④客户端同时匹配通配网段与单主机条目时以单主机为准，特异性相同才按配置顺序取先出现者；⑤specificity 对单主机返回 3、网段返回 2、通配返回 1、不匹配返回 0；⑥缺少某类选项时补默认值：读写方向补 ro，同步方式补 sync，压缩方式补 root_squash，子树检查补 subtree_check，返回按字母升序排列的元组；⑦全用户压缩与根用户压缩同时出现时后者覆盖前者，禁止根用户压缩与全用户压缩并存必须判配置冲突并拒绝加载；⑧authorize 在请求 rw 而生效选项只有 ro 时拒绝，reason 为 READ_ONLY；找不到匹配导出时拒绝，reason 为 NO_EXPORT，此时 export_path 为 None、options 为空元组；放行时 reason 为 OK；⑨子树检查开启时挂载子目录要额外校验父目录可达性，父目录被移出导出后已挂载客户端在下次访问时判失效；⑩register_mount 按登记顺序记录，verify_mount 对未登记、导出已变更或客户端不再匹配的挂载返回 False；⑪快照含 version、entries、mounts、stats 四项且与现场深拷贝隔离，restore 结构不合法抛 NFS_SNAPSHOT_INVALID 且不改现场；⑫stats 暴露 loads、failed_loads、authorizations、denials、mounts、restores 六项计数，denials 只统计 authorize 的拒绝。

两条硬约束：并发重载导出表时，挂载判定只能用完整旧表或完整新表，decision 里的 version 与 options 必须同源，不能一半旧一半新；恢复方面，快照 restore 到新实例后导出表、挂载记录、版本号与计数与快照一致，同一份请求得出同样的结论。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: nfs_export_guard
- typeName: NfsExportGuard

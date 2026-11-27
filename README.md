# batch51-py-safety-c-02

## 题面

行里的构建机上周被安全组拦了一次：一批用自家工具链编出来的程序，启动时总是先到工程目录下的 lib 里找库，那目录全组可写，谁都能往里扔一个同名 .so；同时运维在 /etc/ld.so.conf 里补的目录顺序和程序自己声明的路径谁先谁后，几台机器上表现还不一样，同一份产物在 A 机跑得起来、B 机直接起不来。追下去发现启动器根本没有"这条路径能不能信"的判断，谁先出现在列表里就用谁；另外两台上同一个进程偶尔会看到一半旧目录一半新目录的搜索路径，事后完全无法复现。

需要写一个库搜索路径守卫，落在 gsb/batch51-py-safety-c-02，文件名 loader_path_guard.py，主类 LoaderPathGuard，构造参数 allowed_root、world_writable_dirs。对外接口：load_config(search_dirs, *, source)、current_version()、config_dirs()、expand_origin(pattern, *, binary_path, allowed_root=None)、resolve_search_path(hint, *, env=())、check_binary(hint, *, env=())、explain(hint, *, env=())、mark_world_writable(path)、is_world_writable(path)、cache_key(hint, *, env=())、invalidate_cache()、snapshot()、restore(state)、stats()。hint 是 BinaryHint(path, rpath, runpath, needed)，路径展开时 $ORIGIN 指二进制所在目录。

要落实的边界：①配置条目去掉首尾空白与结尾斜杠后必须是绝对路径，空表、相对路径、非字符串一律判装载失败，抛 LoaderPathError，code 为 LDG_CONFIG_INVALID，旧表和旧版本号保持不动；②可执行文件既没有旧式运行时路径也没有新式路径时，环境变量条目排在配置目录之前；③旧式运行时路径在没有新式路径时先于环境变量生效，一旦存在新式路径，两者顺序互换且旧式路径整条被忽略；④环境变量与配置里的相对路径逐条拒绝，拒绝码 RELATIVE_PATH，其余条目照常参与决议；⑤被标记为世界可写的目录逐条拒绝，拒绝码 WORLD_WRITABLE，标记可以来自构造参数也可以来自 mark_world_writable；⑥$ORIGIN 与 ${ORIGIN} 都按二进制所在目录展开，展开结果做规范化；⑦相对来源展开后含上跳并越出 allowed_root 时整条路径拒绝，不能先规范化再放行；⑧同一目录重复出现只保留首次位置，去重不得改变其余条目的相对顺序；⑨check_binary 返回 LoadDecision，含 allowed、version、path、rejections，rejections 按扫描顺序排列，path 只留可信且去重后的目录；⑩按配置版本驱动的缓存：同一 hint 与环境重复决议命中缓存，配置版本一变缓存立即失效，resolutions 只计真正重算的次数，cache_hits 单独计；⑪snapshot 返回带 version、dirs、world_writable、stats 四键的 dict，stats 是映射，快照与现场深拷贝隔离；restore 结构不合法抛 LDG_SNAPSHOT_INVALID 且不改现场；⑫stats 暴露 config_loads、failed_loads、resolutions、cache_hits、rejections、restores 六项计数。

两条硬约束：并发刷新配置时，决议只能用完整旧表或完整新表，决策里的 version 与 path 必须同源；恢复方面，快照 restore 到新实例后目录表、世界可写标记、计数都要与快照一致，重启后同一份 hint 得出同样的决议。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: loader_path_guard
- typeName: LoaderPathGuard

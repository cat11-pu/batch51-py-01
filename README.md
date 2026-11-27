# batch51-py-safety-c-15

## 题面

制品归档解包流水线这周出了安全事件：一个从外部下载的压缩包带进了文件能力属性，解包后落盘的可执行文件直接带着 cap_net_raw，安全组复现时发现流水线是先写文件再清属性，中间的窗口被利用；另有硬链接归档只给其中一个路径清了能力，另一个链接仍然可提权；还有一次写到一半进程被杀，重启后临时文件残留，半个属性被当成已生效，审计对不上。安全组现在要求提供剥离与写入先后顺序的证据，现有日志里只有最终属性，根本证明不了中间窗口。请修 gsb/batch51-py-safety-c-15 下的 xattr_capability_sync.py，类 XattrCapabilitySync，负责解包前后的扩展属性保留与剥离决策。

对外接口：XattrCapabilitySync(*, max_attrs=32, temp_prefix=".xattr-tmp-")；set_source_trust(source, level)；set_path_policy(prefix, *, allow, conflict="policy")；plan_xattr(path, attrs, *, source)；apply(path, attrs, *, source)；strip(path, names)；inspect(path)；touch(path)；add_hardlink(path, existing_path)；link_targets(path)；remove_path(path)；begin_write(path, attrs, *, source)；commit_temp(temp_id)；pending_temp_files()；cleanup_temp()；operations()；snapshot()；restore(state)；stats()。拒绝时抛 XattrError(code, detail)。计划包含 path、keep、strip 三个字段，keep 按键升序；操作记录按发生顺序追加，动作为 strip、write、replace，形如 (动作, 路径, 名字, 值) 或 (动作, 路径, 名字) 或 (动作, 路径)；stats 返回 applied、written、stripped、replaced、plans、refused 六个计数，written 只统计真正发生的写入，replaced 只统计原子替换；snapshot 返回 version、objects、paths、next_object、trust、policies、operations、temps、next_temp、stats 十个键。inspect 对不存在的路径返回 None；touch 首次创建返回 True，路径已存在返回 False；remove_path 删除成功返回 True，路径不存在返回 False。

要修的点：①可信来源按路径策略保留属性，不可信来源只保留 user. 前缀的属性，security. 与 system. 类一律剥离；②路径策略按最长前缀匹配，allow 支持通配与精确名，allow 为空表示全部剥离；③同名属性冲突由策略的 conflict 决定，取 policy 时保留目标现值，取 source 时用来源值覆盖；④剥离必须先于写入生效，操作记录里同一文件的 strip 项必须排在任何 write 项之前，不允许先落能力再清除；⑤strip 只删指定名字，缺失的名字不计入返回值；⑥apply 对不存在的路径按新建处理，属性按键升序输出；⑦属性条数超过 max_attrs 报 XATTR_ATTR_LIMIT，且在写入任何属性之前拒绝；⑧非字符串属性值、非绝对路径、空来源、非法信任级别、非法策略前缀或冲突取值报 XATTR_INVALID_REQUEST，状态与操作记录都不得改变；⑨apply 遇到相同键值必须幂等，不产生重复写入；⑩add_hardlink 让两个路径共享同一对象，link_targets 返回升序路径，删除其中一个路径后另一个仍可用，向其中一个路径写入或剥离属性必须同时作用于所有链接并按同一对象一次处理；⑪快照深拷贝，restore 校验对象、路径映射、信任表、策略、操作记录与统计，非法报 XATTR_SNAPSHOT_INVALID 且原状态不变；⑫统计要能区分应用次数、实际写入、实际剥离、原子替换、计划次数与被拒次数。

硬约束：并发写入同一路径必须持锁，属性不得丢更新，操作记录的先后与实际写入顺序一致；写入走临时文件再原子替换，替换失败时保留原文件与原有属性，重启时先清理残留临时文件，未提交的临时写入不得出现在正式属性里；属性条数硬上限。解包线程与审计读取并发时，读到的属性与操作记录必须来自同一个已提交状态。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或用固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: xattr_capability_sync
- typeName: XattrCapabilitySync

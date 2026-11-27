# batch51-py-safety-r-04

## 题面

素材站上周被人用一张头像拿到了执行权限：文件头是标准 PNG，尾部却拼了一段 PHP，服务端只看了声明类型和第一个魔数就放行；同一天客服转来一张工单，附件文件名里夹着从右往左的控制符，落盘后被判成 png，实际执行的却是另一个扩展名；压测环境更直接，一个十几 KB 的压缩包展开后写出几十 GB，把上传节点的磁盘打满，预留的额度也没有回收。范围是 gsb/batch51-py-safety-r-04 的 upload_polyglot_quota.py，类 UploadPolyglotQuota，负责内容嗅探、文件名归一、配额预留与解压展开。

公开接口：UploadPolyglotQuota(*, allowed_types=("png","jpeg","gif","pdf"), max_bytes=8388608, max_inflight_bytes=33554432, max_expanded_bytes=67108864, max_entries=256, max_depth=2)；sniff(data)；normalize_filename(raw)；screen(*, filename, declared_type, data)；reserve(upload_id, *, byte_count)；release(upload_id)；pending_reservations()；expand(upload_id, archive_bytes, *, depth=0)；audit_log()；snapshot()；restore(state)；stats()。参数非法或配额冲突抛 UploadError(code, detail)；screen 不抛判定类异常，一律返回带 allowed 与 reason 的结论。

要修的行为：① sniff 按魔数表顺序比对并去重，primary 给出所属族系，命中可执行族（elf、html）时 severity 为 reject，完全未识别为 suspicious，其余为 ok；polyglot 只在命中两个及以上不同族系时为真；② normalize_filename 做小写、去首尾空白与点、删除 NUL 与控制字符，归一后为空或含 / 与 \ 一律 UPLOAD_FILENAME_REJECTED；③ screen 的结论顺序固定为文件名形状、双扩展名、可执行与 polyglot、声明类型核对、允许类型、单文件字节上限，顺序不同会导致原因码不同；screen 返回 ScreeningVerdict，含归一后的 filename、declared_type、sniffed、extension、allowed、reason、reserved_bytes；④ 双扩展名指倒数第二个扩展名落在脚本集合（php、phtml、jsp、asp、cgi、sh、py、js、html、exe、elf 等）里，报 UPLOAD_DOUBLE_EXTENSION；⑤ 声明类型只用 image/png、image/jpeg、image/gif、application/pdf、application/zip 与嗅探结果交叉核对，不一致报 UPLOAD_TYPE_MISMATCH，嗅探类型不在 allowed_types 报 UPLOAD_UNSUPPORTED_TYPE；⑥ reserve 对同一 upload_id 幂等，重复预留返回首次金额且不重复记账，金额不同报 UPLOAD_INVALID_REQUEST；在途预留总额超过 max_inflight_bytes 报 UPLOAD_QUOTA_EXCEEDED；release 返回归还金额，没预留过的 id 返回 0，pending_reservations 返回 upload_id 到金额的字典副本；⑦ expand 要求该 upload_id 已有预留，否则报 UPLOAD_INVALID_REQUEST；⑧ 条目数超过 max_entries 报 UPLOAD_ENTRY_REJECTED，累计展开字节超过 max_expanded_bytes 报 UPLOAD_QUOTA_EXCEEDED，这两种拒绝都必须整包不落地、把预留全额归还、rollbacks 加一、expanded_bytes 不变，拒绝报告里 entries 记已扫描条目数、bytes_written 为 0；⑨ 成功展开返回 entries、bytes_written、depth，把该次预留转为已用，expanded_bytes 累加；⑩ screen 放行计 screened、拒绝计 rejected，每次判定往审计里落一条，含 filename、declared_type、sniffed、reason 与 reserved_bytes；⑪ stats 给出 screened、reserved_bytes、expanded_bytes、rejected、rollbacks、restores 六项；⑫ 快照含 version、reservations、expanded_bytes、audit、stats 五项，取出后与实例不共享可变结构，恢复要校验结构与类型，非法报 UPLOAD_SNAPSHOT_INVALID 且不动现有数据，成功计一次 restores。

另外三个现场要一并兜住：一是文件头同时满足图片与脚本特征时按更严格的类型处理并标注 polyglot，不能取第一个匹配就放行；二是文件名里的 Unicode 双向控制符要在归一阶段剔除干净后再判扩展名，不能让显示顺序和落盘顺序对不上；三是嵌套压缩每层都要重新计配额，条目名里含 ../ 时整包拒绝而不是跳过该条目继续解。

硬约束：并发预留、归还与展开同一个 upload_id 只能生效一次，锁外不得读到半套记账；快照恢复后预留表、已展开量与计数必须自洽；在途预留总额与累计展开量都是硬顶，超限整单拒绝，不允许先写一部分再补记。验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: upload_polyglot_quota
- typeName: UploadPolyglotQuota

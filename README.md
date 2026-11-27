# batch51-py-safety-c-03

## 题面

安全基线每季度要过一遍全量二进制，这一季的抽检直接翻车：清单里标着"已加固"的十几个可执行文件，实际有一半在只读重定位和立即绑定这两项上根本没做，扫描脚本却把它们算成了通过；另一批静态编出来的老服务被脚本判成"只读重定位缺失"，负责人拿着报告来对质，最后发现是扫描器把不适用的项目当成了失败。更糟的是有位同事在扫描窗口里替换了二进制，报告上还挂着旧文件的结果，谁也说不清那份结论对应的是哪一版。

要做的是可执行文件加固审计，落在 gsb/batch51-py-safety-c-03，文件名 elf_hardening_auditor.py，主类 ElfHardeningAuditor。按小端 ELF64 解析：e_type 在偏移 16（2 字节）、e_entry 在 24（8 字节）、e_phoff 在 32（8 字节）、e_phentsize 在 54（2 字节）、e_phnum 在 56（2 字节）；程序头固定 56 字节，p_type 从 0 起 4 字节、p_flags 从 4 起 4 字节、p_offset 从 8 起 8 字节、p_filesz 从 32 起 8 字节；PT_DYNAMIC 指向的区域按 16 字节读 d_tag 与 d_val。对外接口：parse_image(data)、check_image(info, *, symbols=())、verdict_for(items)、scan(path, data, *, package="", symbols=(), now=None)、set_baseline(package, items)、baseline_for(package)、add_exemption(path, digest, items, *, expires_at=None)、drop_exemption(path, digest)、is_exempt(path, digest, item, *, now=None)、report()、stats()、snapshot()、restore(state)、clear()。

要落实的边界：①magic 不是 7f 45 4c 46 抛 ElfAuditError，code 为 ELF_BAD_MAGIC，头部长度不足或 phoff 与 phnum 指向超出文件同样判解析失败；②摘要按 sha256 小写十六进制计算，ImageInfo 带 file_type、entry、phentsize、phnum、size、digest、segments、dynamic，segments 保持程序头原始顺序；③加固项固定为 pie、nx_stack、relro、bind_now、stack_canary，状态只取 ok、fail、n/a，items 顺序固定；④ET_DYN 判地址无关达标，ET_EXEC 判不达标；⑤存在 PT_GNU_STACK 且不带执行位判不可执行栈达标，带执行位判失败；⑥有 PT_GNU_RELRO 判只读重定位达标，动态段出现 DT_BIND_NOW、DT_FLAGS 带 DF_BIND_NOW、DT_FLAGS_1 带 DF_1_NOW 三者之一判立即绑定达标；⑦静态链接的可执行文件没有动态段，只读重定位与符号绑定记为不适用而不是失败；⑧stack_canary 只在传入符号里出现 __stack_chk_fail 时达标；⑨scan 以 path 与 digest 共同定位镜像，同一组合重复扫描复用解析结果，摘要变了就是另一份镜像，旧豁免不得继承；⑩豁免条目带到期时间，到期后即使摘要没变也要重新计入失败；⑪文件名在扫描期间被替换导致摘要变化时，本次结果作废并重扫，不能把旧解析结果贴到新文件上；⑫report 返回 images、packages、failing_items 三键，packages 下每个包给 images 与按加固项固定顺序去重的 failing；set_baseline 按包名放行指定项，没有记录时 baseline_for 返回空元组，放行只影响 failing 与 verdict，items 里的原始状态保持 fail。

两条硬约束：并发扫描同一文件时只解析一次，parses 计数必须停在 1，各自拿到的结论一致；快照恢复方面，images、exemptions、baselines、stats 都要与现场深拷贝隔离，restore 到新实例后同一镜像的结论、豁免与计数与恢复前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: elf_hardening_auditor
- typeName: ElfHardeningAuditor

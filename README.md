# batch51-py-safety-c-01

## 题面

权限侧的巡检这周连着出了两次洋相。第一次是一台灰度机给部署账号单独放开了 root 登录，配置里那段只有部署机器才命中的条件块本身写得没错，可巡检脚本给出的结论是"全量合规"，值班同学照着签了字；第二次更麻烦，同事在 Ciphers 那一行手滑多写了一个拼错的算法名，重载之后机器直接从集群里掉了出去，回滚时又发现巡检侧记的重载次数和实际对不上，谁也说不出当时到底生效的是哪一版。

现在要把这套判断固化成代码，落在 gsb/batch51-py-safety-c-01，文件名 sshd_config_auditor.py，主类 SshdConfigAuditor。构造参数为 config_dir、defaults、strict_ciphers、max_auth_tries、max_include_depth、include_reader；defaults 是"算法关键字到允许出现的算法名元组"的映射，同时充当该关键字的取值白名单。对外接口包括 parse_config(text, *, source)、effective_value(keyword, *, context)、effective_list(keyword, *, context)、effective_config(*, context)、match_applies(block_index, *, context)、audit(*, context)、require_compliant(*, context)、diff(other)、reload(text, *, source)、current_version()、snapshot()、restore(state)、stats()。

需要落实的故障与边界：①关键字统一按小写登记，值保留原始大小写，空行与 # 注释跳过，行号从 1 起算；②只有关键字没有值、条件键不在 user/group/address/localport 之内、Match 后面没有条件，都算解析失败，抛 SshdAuditError，code 为 SSHD_PARSE_FAILED，detail 带 line 与 message；③同一条件块内重复出现的关键字以后者为准，跨条件块按块在文件中的先后合并，先出现的全局值不参与覆盖，没出现过的关键字返回 None；④effective_list 按逗号切分、去重并保留首次出现的顺序，非算法关键字同样适用；⑤算法关键字 ciphers、macs、kexalgorithms 的取值必须全部落在 defaults 对应元组里，全部合法时原样返回且顺序不得重排；⑥条件键不区分大小写，user 与 group 用通配符匹配，address 按 CIDR 归属判断，localport 按字符串相等判断，一条块的多个条件必须全部命中才算生效；⑦Include 指令的相对路径按 config_dir 解析而不是进程工作目录，包含深度超过 max_include_depth 或形成包含环都判解析失败；⑧算法列表混进未收录的名字时这条指令整体作废并回退到该关键字的默认列表，不允许剔掉未知项继续用剩下的值；⑨audit 按 permitrootlogin、passwordauthentication、maxauthtries、ciphers 的固定顺序产出 finding，报告只含 version、context、findings、verdict、counts，counts 只有 ok 与 deny 两个键，verdict 只取 allow 与 deny；require_compliant 在 deny 时抛 SshdAuditError，code 为 SSHD_POLICY_REFUSED，detail 的 failed 是失败关键字元组；⑩reload 成功时版本号加一并原子替换，解析失败抛 SSHD_PARSE_FAILED，旧配置、旧版本号、旧生效值一律不动，stats 暴露 parses、reloads、failed_reloads、audits、restores 五项计数；⑪diff 只比较全局生效值，按关键字升序返回 ConfigChange，新增项 before 为 None，被删掉的项 after 为 None；⑫snapshot 返回带 version、config、stats 三键的 dict，config 与 stats 都是映射，且与现场深拷贝隔离；restore 遇到结构不合法的状态抛 SSHD_SNAPSHOT_INVALID 并且不改动现场。

两条硬约束：并发方面，reload 与 audit 同时进行时 audit 只能看到完整的旧版或完整的新版，report 里的 version 与 findings 必须同源；恢复方面，把同一份快照 restore 到新实例后，生效值、版本号、各项计数都要与恢复前一致，不能丢也不能重复累计。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: sshd_config_auditor
- typeName: SshdConfigAuditor

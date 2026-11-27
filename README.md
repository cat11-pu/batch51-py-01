# batch51-py-safety-c-43

## 题面

镜像仓库这周被外部审计摆了三张截图：一张是线上镜像的最终层，USER 写的是数字 0，扫描器只认字面 root，给了合规；一张是多阶段构建的产物，最终阶段里干干净净，可 COPY --from 从构建阶段带进来的 .npmrc 还躺在镜像里；还有一张是 ENV 里改过的数据库口令，后一层把变量覆盖成了占位符，旧值仍留在层历史里，报表却只看最后一层，结论是“无敏感信息”。三张截图指向同一个问题：审计口径太粗，把有风险的镜像判成了通过。审计组希望每次给出结论时都能指到具体层、具体键和具体文件，而不是只报一个总分。

范围是 gsb/batch51-py-safety-c-43，文件名 image_config_auditor.py，主类 ImageConfigAuditor，记录类型 EnvEntry、Layer、ImageConfig、Finding，异常统一抛 ImageAuditError(code, detail)。配置来自构建系统导出的 JSON，最终阶段配置与层历史都在同一个 payload 里。

对外接口：ImageConfigAuditor(*, max_layers=40, max_config_bytes=65536)；load_config(payload)；audit_user(user=None)；scan_env()；check_entrypoint()；check_base_image()；check_ports()；check_healthcheck()；check_layers()；audit()；report()；snapshot()；restore(state)；stats()。

需要落实的故障与边界：①image 必须是非空字符串，digest 必须是 sha256 加 64 位十六进制，端口只接受整数或“端口/协议”，env 只接受映射或二元组列表，层记录缺字段同样算结构错误，一律抛 IMAGE_CONFIG_INVALID；②层数超过 max_layers 或序列化后的配置超过 max_config_bytes 抛 IMAGE_LIMIT_EXCEEDED；③USER 为空、只含空白、root 或数字 0 判高危 IMAGE_ROOT_USER，数字 UID 与非 root 用户名按归一后的身份判断；④ENV 与层历史里的键名按口令、令牌、密钥、凭据模式识别，连接串按 scheme://user:pass@ 识别，finding 只带键名、长度与层号，detail 用 key、length、layer 三个字段记录，绝不能出现值；⑤entrypoint 为字符串即 shell 形式，判 medium 的 IMAGE_SHELL_ENTRYPOINT，detail.form 固定为 shell，exec 数组形式不报，缺失报 low 的 IMAGE_NO_ENTRYPOINT；⑥EXPOSE 小于 1024 的特权端口逐个报 high 的 IMAGE_PRIVILEGED_PORT，detail.port 带端口号，其余端口放过；⑦基础镜像必须按 digest 固定，缺 digest 报 medium 的 IMAGE_UNPINNED_BASE；⑧缺 HEALTHCHECK 报 low 的 IMAGE_NO_HEALTHCHECK；⑨层历史里被删除的文件仍算泄露，删除动作只改变当前层视图，历史层里的内容仍可被还原，逐个报 high 的 IMAGE_DELETED_FILE_LEAK，detail.path 带文件路径并保留层号；⑩多阶段构建只审计最终阶段的配置，但 COPY --from 从其它阶段带入的文件要按来源阶段追溯，不能因为最终阶段干净就判通过；⑪ENV 在后续层被覆盖时，历史层里的旧值仍算泄露，报告保留层号；⑫audit 按 high、medium、low 排序，同级按 code 与 subject 升序；report 输出 image、digest_pinned、verdict、counts、findings、audits，counts 含 high、medium、low 三项；stats 至少暴露 loads、audits 两项计数；snapshot 深拷贝 version、config、findings、stats 四个键，restore 遇非法结构抛 IMAGE_SNAPSHOT_INVALID 且现场不变。

两条硬约束：并发审计共用实例时结论与计数不得串台，也不能把同一批 finding 重复累加；快照恢复到新实例后，配置、结论与计数必须与恢复前一致，不能丢也不能重复累计。审计结果要可复核，同一份配置多次审计的输出顺序必须一致。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: image_config_auditor
- typeName: ImageConfigAuditor

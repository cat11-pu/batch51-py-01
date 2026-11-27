# batch51-py-safety-c-45

## 题面

素材站上周被白帽子传了一张头像，五分钟后同一目录下多出一个能直接执行的文件。复盘时三种情况同时存在：上传接口返回 200，但文件被改名成一串随机字符，旧脚本只看状态码就记了成功；图片马的魔数在服务端被放行，扩展名又被改回 .php，前端只验证了魔数通过就宣布绕过；同名文件重复上传时第二次也回 200，内容其实没更新，脚本连读都没读就下了结论。值班最初把这三次都记成“已阻断”，直到红队把执行结果截图发过来。运维要求把“传上去了”和“能被当成代码取回”彻底分开，任何结论都要有取回证据。

范围是 gsb/batch51-py-safety-c-45，文件名 upload_filter_bypass_prober.py，主类 UploadBypassProber，记录类型 Variant、UploadPart、SubmitResult、BypassVerdict，异常统一抛 UploadError(code, detail)。

对外接口：UploadBypassProber(*, transport, max_uploads_per_target=8, max_bytes=2000000, max_variants=12)；plan(base_name="shell", *, kinds=None)；build_part(variant)；submit(target, variant)；judge(submission, *, fetch=None)；report()；snapshot()；restore(state)；stats()；submissions_for(target)；reset()。

需要落实的故障与边界：①变体固定十种，依次取 shell.php.jpg 配 image/jpeg、shell.PHP 配 application/x-php、shell.php. 配 application/octet-stream、带尾随空格的 shell.php 配 application/octet-stream、全角点的 shell．php、shell.php\x00.jpg 配 image/jpeg、.htaccess 与 .user.ini 配 text/plain、shell.jpg 配 application/x-php、带 GIF89a 头的 shell.jpg 配 image/jpeg，顺序固定，kinds 按固定顺序过滤，超过 max_variants 截断，未知变体抛 UPLOAD_VARIANT_UNKNOWN；②基础名不能为空或只含空白、不能含路径分隔符，否则抛 UPLOAD_INVALID_REQUEST；③multipart 分片必须带 boundary、filename、Content-Type 与二进制体，魔数位于体首，尾部有闭合边界；④单目标上传次数与单文件字节数硬顶，超限抛 UPLOAD_LIMIT_EXCEEDED 且不得调用传输层；⑤判定必须做二次取回，只有上传成功不算命中，取回内容含执行标记才判 bypass，取回 404 判 blocked/not_reachable，evidence.url 记录取回地址，submit 记录状态、访问 URL、存储路径与响应头，头名统一小写；⑥上传返回 200 但文件被重命名为随机串时，要按响应路径或已知目录验证可达，不能直接判成功；⑦图片魔数通过但扩展名改为 .php 的变体，只有服务端按魔数放行且 Web 服务器按扩展名执行才算命中，只满足一半标 partial；⑧同名文件已存在时覆盖策略可能让第二次上传成功但内容未更新，判定要读回内容而不是只看状态码；⑨WAF 拦截与 403 按不可判定处理，5xx 同样不可判定，400、413、415 判拒绝；⑩存储路径与访问 URL 分别验证，缺一不可；⑪同一目标的并发提交必须串行，report 输出 targets、submissions、counts、bypass，counts 含 bypass、partial、blocked、inconclusive 四个键，stats 含 uploads、judgements、bypass、blocked；⑫snapshot 深拷贝 version、submissions、verdicts、stats 四个键，restore 遇非法结构抛 UPLOAD_SNAPSHOT_INVALID 且现场不变。

两条硬约束：并发侧锁粒度按目标，多线程同时提交同一目标时任意时刻只能有一个分片在途；上限侧上传次数、单文件大小与变体数量同时生效，超限必须在发出请求前拒绝，不能先传后报错。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: upload_filter_bypass_prober
- typeName: UploadBypassProber

# batch51-py-safety-b-14

## 题面

递归解析器把上游 UDP 改成 TCP 长连接后，解析结果开始串号：两条在途查询的响应乱序到达，被按到达顺序配对，查 a.example 的客户端拿到了 b.example 的地址；连接半关闭时缓冲区里剩下的半帧被当成下一条报文，解析出错误的 ID；旧查询超时释放后 ID 被复用，迟到的旧响应又命中了新查询。值班同学起初怀疑上游抖动，后来发现同一连接上两个客户端的解析记录被互换了。问题定位在 gsb/batch51-py-safety-b-14 的 dns_tcp_pipeline_guard.py，类型 DnsTcpPipelineGuard，管理单条 TCP 连接上的查询流水线、两字节长度分帧与未完成查询表，拒绝统一抛 PipelineError(code, detail)。

对外接口保持：attach_connection(conn_id, now)->ConnectionView；submit_query(conn_id, qid, qname, qtype, now)->QueryView；accept_response(conn_id, message, now)->Delivery；feed(conn_id, data, now)；half_close(conn_id, now) 与 close_connection(conn_id, now)；expire_queries(now)、expire_idle(now)；in_flight、connection_view、connections、framing_stats、snapshot/restore、stats。

需要修好的行为：①每条报文以两字节长度前缀分帧，零长度、声明长度与实际不符、声明超过 max_frame 分别报 PIPELINE_FRAME_ERROR 或 PIPELINE_FRAME_TOO_LARGE，并关闭连接；②accept_response 只接受单条完整帧，feed 负责流式缓冲，未成帧字节留在 pending_bytes，不得当作下一条报文；③响应按 (id, qname, qtype) 匹配，qname 大小写不敏感，不按到达顺序配对；④同一连接允许多个在途查询，重复响应只交付一次，第二次记 duplicate；⑤旧查询未完成时同 ID 新查询报 PIPELINE_ID_IN_USE，超过 max_in_flight 报 PIPELINE_IN_FLIGHT_LIMIT；⑥qid 不在 0 到 65535、qname 为空或超过 255、qtype 不在支持集合，一律报 PIPELINE_INVALID_QUERY；⑦旧查询超时释放槽位后，同一 ID 可以立刻被新查询复用，但迟到的旧响应必须再校验 qname 与 qtype，不得命中新查询；⑧连接半关闭后仍要交付已经缓冲的完整响应，未成帧的残余字节不得当作下一条报文；⑨响应 question 段与请求大小写不同时按不敏感匹配，压缩指针必须能正确解析；⑩单查询超时回 servfail 并释放槽位，连接空闲与单查询超时分别计时，expire_idle 关闭空闲连接；⑪关闭连接时在途查询统一回 servfail，之后提交报 PIPELINE_CONNECTION_CLOSED；⑫连接总数、单连接在途数、帧长度都是硬上限，超限只能拒绝。

硬约束：feed、accept_response 与 close_connection 会被读写两个协程同时调用，帧缓冲与在途表必须持锁更新，任何时刻都不能出现半帧被两个线程各解析一次；快照要带走连接、缓冲字节、在途查询、ID 占用与统计，restore 遇到版本不符抛 PIPELINE_SNAPSHOT_INVALID 且现场不变。帧缓冲长度按字节计，积压不得无限增长。统计接口 stats 按 queries、delivered、duplicates、unmatched、timeouts、idle_closed、frame_errors 如实计数，不得估算。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，测试不得修改、不得跳过、不得按固定输入写死；乱序响应、半关闭交付与重启恢复请自行构造场景验证并留下执行记录；只做本地实现，交付源码、测试记录与改动说明，不改上游仓库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: dns_tcp_pipeline_guard
- typeName: DnsTcpPipelineGuard

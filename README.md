# batch51-py-game-c-02

## 题面

剪辑组这周连续报同一类问题：时间线上明明贴的是 A 机位的代理，放出来却是 B 机位刚才那条；重新挂一次有时能好，有时把整段素材挂成空白。转码机那边也在抱怨，同一段 4K 素材排了十几遍，队列里躺着一模一样的任务，真正要等的却还排在后面。还有人把素材从卡上重新拷了一遍，画面内容一个字没变、只是文件时间戳变了，第二天整批代理又重转了一轮，机房风扇转了一夜。

范围收到代理生成与重链接这一层，代码在 gsb/batch51-py-game-c-02 的 proxy_media_planner.py，类 ProxyMediaPlanner，负责按素材、校验和与分辨率档位排队生成代理，维护任务状态，并把时间线上的引用重新挂回可用的代理。

公开接口：ProxyMediaPlanner(*, tiers=("half","quarter","eighth"), max_tasks=16, max_workers=2, max_attempts=3)；enqueue(asset_id, *, checksum, tier, mtime=None)；start_next()；complete(task_id, *, output_path)；fail(task_id)；progress(task_id)；resolve(asset_id, *, tier)；relink(asset_id, *, checksum, tier)；invalidate(asset_id, *, checksum=None)；snapshot()；restore(state)；stats()。拒绝时抛 ProxyError(code, detail)。TaskRecord 记录 task_id、asset_id、checksum、tier、status、attempts、output_path、stale。

故障与边界：

一、asset_id 与 checksum 去掉首尾空白后为空、tier 不在 tiers 里，一律 PROXY_INVALID；tiers 为空、含重复或空档位，以及 max_tasks、max_workers、max_attempts 小于 1，构造时抛 PROXY_INVALID_CONFIG。

二、任务状态只有 queued、running、done、failed、invalid 五种。progress 对未知 task_id 报 PROXY_UNKNOWN，返回字典含 task_id、asset_id、checksum、tier、status、attempts、output_path。

三、enqueue 把任务排进队列尾部，返回 status 为 queued、attempts 为 0 的记录；在办任务（queued 加 running）数达到 max_tasks 时抛 PROXY_CAPACITY，done、failed、invalid 不占名额。

四、start_next 按入队先后取最早的 queued 任务转成 running 并返回 task_id；没有可取的任务，或 running 数已达 max_workers 时返回 None，且不得改动任何任务。

五、complete 只接受 running 任务（否则 PROXY_INVALID_STATE），未知 task_id 报 PROXY_UNKNOWN，输出路径去空白后为空报 PROXY_INVALID；成功后 status 为 done 并记下去空白后的输出路径。

六、fail 只接受 running 任务（否则 PROXY_INVALID_STATE），attempts 加一；未达 max_attempts 时回到 queued 并排到队尾，达到上限后 status 变 failed，failed 计数加一。

七、resolve 只认 done 任务：同素材同档位有多条时取最近完成的一条；没有完成但还有在办任务时报 PROXY_NOT_READY，该素材该档位一条都没有报 PROXY_UNKNOWN。

八、relink 只在该素材该档位该校验和已经有完成代理时返回输出路径，否则报 PROXY_NOT_READY，素材完全没进过队列报 PROXY_UNKNOWN。

九、invalidate 把该素材尚未失效的任务置为 invalid 并返回条数，带 checksum 时只处理该校验和；重复调用返回 0；之后 resolve 与 relink 对这批任务报 PROXY_INVALIDATED；同一组参数重新入队必须生成新的 task_id，不得复活旧任务。

十、snapshot 返回 version、next_task、tasks、stats 四个键，tasks 是列表，每项含 task_id、asset_id、checksum、tier、status、attempts、output_path、mtime；快照是深拷贝，改快照不影响实例。

十一、restore 对缺键、类型不对、状态取值不认识或 version 不认识的快照抛 PROXY_SNAPSHOT_INVALID，原状态一字不动；合法快照恢复后任务状态、尝试次数、输出路径与 stats 都要一致，队列顺序按快照里的先后还原。

十二、stats 固定返回 enqueued、started、completed、failed、invalidated、retries、live 七个键；enqueued、started、completed、failed、invalidated、retries 是累计值，live 只算当前状态为 queued 与 running 的任务。

硬约束：同一素材同一档位的生成任务在同一时刻只允许存在一个，重复入队返回同一份任务记录，不得重复建任务；同一素材的不同档位可以并行；源文件的修改时间不参与身份判定，只有画面校验和变了才算换了源。任务队列与状态迁移会被多个转码 worker 并发调用，running 数不得超过 max_workers，计数不得丢更新。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行处理；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: proxy_media_planner
- typeName: ProxyMediaPlanner

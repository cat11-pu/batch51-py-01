# batch51-py-safety-c-25

## 题面

安全运营的凭据巡检这周交不出可信报告：同一个密钥在三个提交里都出现过，报告里却只算了一处，另外两处的文件路径完全没被提到；一次目录改名之后，旧路径的命中结果全丢了，值班以为问题已经修掉；还有一次巡检跑了一半被限流打断，第二天从头再来，同一个对象被重复计了三次，统计数字对不上。范围是 gsb/batch51-py-safety-c-25 下的 git_blob_secret_sweeper.py，类 GitBlobSecretSweeper，负责按提交图收集对象、对每个对象只扫一次、把结果回填到所有引用路径，并支持按游标续扫。

公开接口：GitBlobSecretSweeper(*, max_objects=500, rename_threshold=0.6)；add_commit(commit_id, *, parents=(), objects=())；register_blob(oid, *, content)；walk_commits(*, from_commit=None)；scan_object(oid, *, content=None)；sweep(from_commit=None)；resume(cursor)；checkpoint()；follow_renames(commit_id)；results_for_path(path)；describe_commit(commit_id)；snapshot()；restore(state)；stats()；reset()。objects 是 (路径, 对象号) 对的序列。拒绝时抛 SweepError(code, detail)。

要修的行为：① commit_id 为空抛 SWEEP_INVALID_COMMIT，重复登记抛 SWEEP_DUPLICATE_COMMIT，同一提交内路径重复抛 SWEEP_DUPLICATE_PATH（detail 为路径），对象对格式不对抛 SWEEP_INVALID_OBJECT；② add_commit 返回 commit、objects、parents、missing_parents 四个字段，parents 为父提交条数，missing_parents 为尚未登记的父提交元组；③ walk_commits 从指定提交（缺省为最后登记的提交）先序深度优先，父提交按登记顺序展开，每个提交只出现一次，未登记的父提交不进结果；④ 未登记的提交上调用 walk_commits、follow_renames、describe_commit 一律抛 SWEEP_UNKNOWN_COMMIT；⑤ 扫描三类：AKIA 加十六位大写字母数字记 aws_access_key_id，-----BEGIN 与 PRIVATE KEY----- 之间的私钥头记 private_key_block，secret 或 token 赋值后跟十六位以上十六进制串记 hex_secret_assignment，行号按正文换行数从 1 计；⑥ scan_object 返回 oid、findings、cached、bytes 四个字段，findings 是按出现位置排序的元组，每项含 kind 与 line，content 省略时用登记过的正文，找不到抛 SWEEP_UNKNOWN_OBJECT；⑦ 同一对象号只真正扫描一次，之后命中缓存时 cached 为 True，扫描次数不再累加；⑧ sweep 按遍历顺序处理提交，同一对象在多个提交或多个路径出现只扫一次，结果回填到所有引用路径，results_for_path 给出该路径命中的类别元组；⑨ 重命名按父提交的删除路径与本提交的新增路径配对，对象号相同直接配成一对，否则按路径相似度打分，取分数最高且不低于 rename_threshold 的一对一配对；⑩ 游标记录已扫过的提交与对象数，resume 先校验游标里的提交确实扫过，否则抛 SWEEP_INVALID_CURSOR，校验通过后只处理未扫过的提交并返回本次扫过的提交数；⑪ 合并提交两侧各自引入同一对象时只计一次，但两条路径都要出现在结果里；⑫ 浅克隆缺少父提交时按不完整历史标注，不得把缺失部分当作已扫描。

describe_commit 返回 commit、parents、objects、paths 四个字段。sweep 返回 commits、objects、cached、findings、pending 五个字段，pending 是引用了但还没登记正文的对象数。checkpoint 返回 commit、objects 两个字段，commit 为最近一次扫到的最后一条提交。stats 返回 commits、objects、cached、findings、scans、restores 六个计数；扫描对象数受 max_objects 硬顶，超出抛 SWEEP_OBJECT_LIMIT；reset 清计数、扫描缓存与游标，提交图与已登记正文保留。

硬约束：同一实例被多个线程同时 sweep、add_commit 与 scan_object 时，计数与结果表不得互相覆盖，一个对象在一次运行里最多真正扫描一次；快照必须深拷贝，restore 后提交图、已登记正文、扫描结果、游标、默认起点与计数原样往返，结构不符抛 SWEEP_SNAPSHOT_INVALID 且原状态一字不动；对象扫描总量是硬顶，任何重复引用与续扫路径都不能突破。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: git_blob_secret_sweeper
- typeName: GitBlobSecretSweeper
- file: git_blob_secret_sweeper.py

# batch51-py-safety-c-29

## 题面

WAF 绕过验证这周被安全委员会打回：同一条种子载荷生成的几十个变体里，一大半只是编码层数不同，解码后完全等价，却各自占了一个验证名额；更糟的是，回验程序把请求超时的变体也记成了“被拦截”，绕过面被低估了一截；还有一组大小写加注释插入的组合变体，被当成重复项去重掉，实际在目标侧语义并不相同。范围是 gsb/batch51-py-safety-c-29 下的 waf_payload_mutator.py，类 WafPayloadMutator，负责按编码层递增生成变体、按解码后的规范化形式去重，并用回验结果收敛有效集合。

公开接口：WafPayloadMutator(*, max_layers=2, max_variants=16)；add_seed(seed_id, payload, *, case_sensitive=True, comments_active=True)；remove_seed(seed_id)；mutate(seed_id)；combine(seed_id, *kinds)；dedupe(variants)；normalize(payload, *, case_sensitive=True, comments_active=True)；validate_echo(variant_id, *, status_code, echo=None)；rank(seed_id)；survivors(seed_id)；variant(variant_id)；snapshot()；restore(state)；stats()；reset()。拒绝时抛 WafError(code, detail)。

要修的行为：①add_seed 要求种子标识非空且唯一、载荷为非空字符串，违反分别抛 WAF_DUPLICATE_SEED、WAF_INVALID_SEED；未知种子上的操作抛 WAF_UNKNOWN_SEED。②mutate 按固定顺序产出：urlencode_l1 到 urlencode_lN 逐层整体百分号编码，layer 记对应层号；随后 case_swap 整体换大小写、comment_pad 把每个空格换成四个字符的注释块、space_to_plus 把空格换成加号，这三类 layer 记 0；层数到 max_layers 即停止。③变体总量受 max_variants 硬顶，超出部分不生成并计入 suppressed。④normalize 循环解码百分号直到不再变化，注释块按一个空格处理，连续空白压成一个空格并去掉首尾空白，大小写按 case_sensitive 决定是否保留。⑤dedupe 以种子方言下的规范化形式为键，重复只保留首次出现，顺序不变。⑥combine 按传入顺序叠加变换，未知种类抛 WAF_INVALID_KIND，变体标识为“种子@combo:种类加号连接”。⑦validate_echo 的状态只有四种：状态码 2xx 且回显规范化后与种子一致记 equivalent；2xx 但回显不同记 different；403、406、429 记 blocked；请求根本失败记 unverified。⑧rank 按等效优先、未验证其次、不同再次、被拦截最后，同档按层数升序再按标识升序；survivors 只返回 equivalent 的标识并升序。⑨大小写与注释插入组合出的变体，在目标侧语义不同时不得互相去重，方言会决定注释块是否算空白。⑩回验请求失败按未验证处理，不得当成被拦截计入失败样本。⑪快照返回 version、seeds、variants、validations、stats 五项且为深拷贝，恢复后种子、变体、回验状态与计数原样往返，结构不符抛 WAF_SNAPSHOT_INVALID 且当前状态一字不动。⑫stats 返回 seeds、variants、deduped、validated、equivalent、different、blocked、suppressed、restores，其中 variants 为已生成变体总数。

硬约束：变体总量与编码层数都是硬顶，任何叠加路径都不能突破；回验按变体标识幂等，同一变体重复回验以最后一次为准且计数不重复累加；恢复后已生成的变体与回验结论要和中断前一致。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: waf_payload_mutator
- typeName: WafPayloadMutator
- file: waf_payload_mutator.py

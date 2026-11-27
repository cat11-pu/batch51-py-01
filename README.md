# batch51-py-safety-a-05

## 题面

客服转来两起盗刷：同一枚安全密钥在两个城市同时登录都没拦住，另一枚的签名计数被压回旧值也没有告警；运维把疑似克隆的凭据隔离后，人工复核放回来当天又被复用了一次。范围是 gsb/batch51-py-safety-a-05 的 authenticator_clone_detector.py，类 CloneDetector，在每次认证通过后记录签名计数并识别克隆特征。

公开接口：CloneDetector(*, quarantine_after=2)；register_credential(account, *, credential_id, counter_capable=True, at=0)；observe(account, *, credential_id, counter, at)；credential_state(credential_id)；list_credentials(account)；quarantine(credential_id, *, reason, at=0)；release_after_review(credential_id, *, reviewer, at)；revoke_credential(credential_id)；login_allowed(account, *, credential_id)；account_summary(account)；reviews(credential_id)；snapshot()；restore(state)；stats()。时间参数为整数 epoch 秒。

要修的行为：① 凭据登记后处于活跃状态、计数水位为 0，同一凭据号不能重复登记，账号与凭据的绑定关系要能查，账号与凭据不匹配时按未知凭据拒绝；② 计数严格递增时判通过并把水位推到最新值，每条凭据的水位彼此独立；③ 计数后退判回归并回告警，水位保持不动，回归次数要累计；④ 同一秒内连续两次相同计数同样判回归，不能当成正常重放放过，无计数能力的认证器首次从 0 到 0 不算回归；⑤ 回归次数达到 quarantine_after 时自动隔离，隔离后该凭据的登录一律拒绝，且不得因为重新登记或再次认证自动解除；⑥ 人工复核放行只解除隔离，计数水位必须保留而不是清零，否则下一次克隆可以接着用旧计数；⑦ 人工复核要记录复核人与时间，未处于隔离状态的凭据不接受复核；⑧ 计数必须是非负整数，布尔、负数、字符串、小数一律按非法计数拒绝；⑨ 撤销后的凭据不可登录也不可再观测，重放旧的认证响应只能拿到撤销原因；⑩ 同一账号下某枚凭据被隔离，不影响账号下其他凭据的判定与登录；⑪ 账号摘要按状态给出凭据数、活跃数、隔离数、撤销数与回归总数；⑫ 快照要能还原凭据状态、水位、回归次数与复核记录，恢复后不共享可变结构，结构非法按原因码拒绝且不动现有数据；stats 至少给出凭据数、观测数、回归数、隔离数、复核放行数与撤销数六项计数。

运维最关心的是隔离动作要说得清来路：是自动判出来的克隆，还是人工先按住等复核，两种来源都要能追溯；复核放行之后也不能因为重新登记就把旧账一笔勾销。账号维度还要能看出名下几枚凭据各自的状态，方便客服回电。

硬约束：同一凭据并发认证要串行裁决，水位与回归次数不得丢更新；隔离状态的解除只能走人工复核，任何自动路径都不许清掉水位；快照恢复后水位与状态必须自洽。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: authenticator_clone_detector
- typeName: CloneDetector

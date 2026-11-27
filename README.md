# batch51-py-safety-r-05

## 题面

值班这周连着三个班次被模板这块拖住：运营在内容后台改了一段展示表达式，上线后页面把进程里的内部对象直接喷进了响应；把根变量收窄之后，另一个站点靠一个过滤器把参数里的调用链带进了运行时；再后来有人用 include 把配置目录里的文件拼进了页面。问题不在渲染引擎本身，而在渲染之前的判定环节形同虚设：属性链只看第一段、过滤器只看名字、include 只做非空检查。范围是 gsb/batch51-py-safety-r-05 的 ssti_context_guard.py，类 SstiContextGuard，负责在表达式进入渲染器之前拦下越界的属性、过滤器与模板引用，并把每次放行和拒绝都记进审计。

公开接口：SstiContextGuard(*, policy=None)；tokenize(expression)；analyze_expression(expression)；check_attribute_chain(chain)；check_filter(name, args=())；adjudicate(expression, *, subject="")；resolve_include(path, *, from_template="")；register_template(name, source)；adjudicate_template(name)；templates()；render(template, expression, context)；set_policy(policy)；policy()；audit_log()；stats()；snapshot() 与 restore(state)。拒绝统一抛 SstiError(code, detail)。

要修的故障与边界：①词法切分只认名称、数字、带引号字符串、点、竖线、括号、逗号、方括号和加号，offset 从 0 计；空串或纯空白报 SSTI_EMPTY_EXPRESSION，无法识别的字符报 SSTI_LEX_ERROR 且 detail 带 offset。②语法只接受 name(.name)* 与竖线接过滤器名，其余写法报 SSTI_UNSUPPORTED_SYNTAX。③深度按 1 加属性段数加过滤器个数算，超过 max_depth 报 SSTI_DEPTH_EXCEEDED，detail 为 {"depth": 实测, "max_depth": 上限}。④根名不在策略 roots 里报 SSTI_UNKNOWN_ROOT，detail 为 {"root": 名}；词法单元数超过 max_tokens 报 SSTI_LIMIT_EXCEEDED。⑤属性按白名单逐段判定，第一处不允许的段报 SSTI_ATTRIBUTE_DENIED，detail 为 {"segment": 段, "index": 从 0 计}。⑥被双下划线包裹的段一律 SSTI_DUNDER_DENIED，写进白名单也不放行。⑦过滤器必须在本策略清单内，越界报 SSTI_FILTER_DENIED，detail 为 {"filter": 名, "position": 从 0 计}；过滤器参数里的表达式要继续往下判，不能只看过滤器名。⑧表达式里用字符串拼接凑属性名属于静态不可判定，按 SSTI_DYNAMIC_ATTRIBUTE 拒绝，不能放行后交给运行时兜底。⑨include 先归一化：合并点段与双点段、折叠重复斜杠；绝对路径、含反斜杠、越出模板根一律 SSTI_INCLUDE_ESCAPE，空路径报 SSTI_INVALID_INCLUDE，成功时返回相对模板根的路径。⑩extends 的父模板必须落在模板根内，子模板覆盖的每个 block 里的表达式都要单独裁决，不能因为父模板已经放行就整体跳过。⑪render 必须先裁决再取上下文，被拒时一次都不许读 context；内置过滤器 upper、lower、escape 从左到右串接，escape 做 HTML 转义。⑫adjudicate、include 与 render 每次都落一条审计，seq 从 1 递增不重号，拒绝同样落审计并计入 denied。

硬约束：同一实例上的裁决、审计与计数持同一把锁串行，八路并发下 seq 不得重号也不得跳号；快照深拷贝策略、模板、审计与计数，恢复后策略与计数逐项一致，非法快照整份拒绝且不动现有状态；深度与词法单元数都是硬顶，超限即拒不做截断。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发裁决与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: ssti_context_guard
- typeName: SstiContextGuard

# 本地取证查询工具

只读查询：基于字段单元键名册、终态快照、人工核对单、完备日志精确写与缺段
声明，回答“历史位置 p 的键 k 当时是什么值、凭哪份材料”。
**不补造缺失交易，不回写快照或任何输入材料**（运行前后输入文件字节不变）。

## 运行

```bash
python3 -I forensic_query.py 案卷.json                 # 用案卷内 queries
python3 -I forensic_query.py 案卷.json -q 查询.json    # 独立查询批次
python3 -I forensic_query.py 案卷.json -o 结果.json
python3 -I -m unittest discover -s tests -v            # 测试
```

退出码：`0` 正常；`1` 读文件/JSON 解析失败；`2` 材料结构无效
（输出 `structural_error`，与业务层面的证据冲突严格区分）。

## 案卷格式

```jsonc
{
  "history": {"lo": 0, "hi": 1000000000000},  // 历史位置半开区间 [lo,hi)
  "keys": ["balance", "owner"],                // 有限字段单元键名册
  "snapshot": {                                // 可选；position 缺省为 hi-1
    "position": 999999999999,
    "values": {"balance": 4200, "owner": "alice", "risk_flag": null}
  },
  "checks": [                                   // 人工核对单：点实据
    {"id": "chk-001", "position": 100, "key": "balance", "value": 1000}
  ],
  "writes": [                                   // 精确写：挂在变更边界 position
    {"id": "w-010", "position": 500, "key": "balance",
     "before": 1000, "after": 2500}             // before/after 至少给一个
  ],
  "gaps": [                                     // 缺段：受影响边界的半开范围
    {"id": "gap-A", "range": {"a": 400, "b": 410}, "keys": ["balance"]},
    {"id": "gap-B", "range": {"a": 800, "b": 805}, "keys": null}
  ],
  "queries": [{"position": 250, "key": "balance"}]
}
```

## 语义要点

- **边界模型**：位置 p 的变更指 p-1 → p。合法历史位置为 `[lo,hi)`，
  合法变更边界为 `(lo,hi]`。写的 `before` 约束 `p-1`，`after` 约束 `p`。
- **值类型**：整数（拒绝 bool）、字符串、明确 `null`。
  核对单缺 `value` 字段不算空值，属结构无效。
- **强制阻断**：只要某键列出精确写，即使只给 before/after 一侧，
  该边界也切断连续性，缺的一侧不得推断为与另一侧相同。
- **缺段**：`[a,b)` 内受影响键可能被改写且无精确写（否则结构无效）。
  切断边 `(a-1,a)..(b-2,b-1)`：位置 `a..b-2` 各自孤立，
  位置 `b-1` 经未阻断边 `(b-1,b)` 连向右侧。
  `keys: null` 表示全体键，内部只存一份，不按键复制。
- **连续性与结论**：阻断边界之外，同一值证据可向任意方向使用。
  对查询位置所属的可连续取值区间：
  - 区间内实据唯一一致 → `confirmed`，给实据清单与适用区间；
  - 同一区间内出现互相矛盾的真实证据 → `conflict`，列出双方材料；
  - 区间内无任何实据（缺段孤立点只认恰好落在该点的实据）→ `insufficient`。
  跨缺段不能推值的键不影响别的键，也不妨碍该键在段另一侧靠独立证据出结论。
- **结构无效 vs 业务冲突**：越界、类型错、未登记键、id 重复、
  缺段包住精确写、空键名册等整卷拒绝（exit 2）；真实材料互相矛盾则
  正常返回 `conflict`。
- **稀疏大区间**：全部计算基于区间合并 + 二分，内存与耗时只随
  材料/查询条数增长，与历史位置数量无关（已用 10¹² 跨度验证）。

# 案卷发布器（archive_publisher.py）

各保管组陆续交来完整日志分卷（区段可重叠，可整卷替换或撤回）。发布器把
一批分卷变动合入当前版本，产出一版**可直接交给 forensic_query.py 查询的
案卷**以及对应的**来源清单**：每条采信精确写可追到提供侧值的分卷，每处
材料分歧可追到各卷“列写 / 未列写”的主张。

```bash
python3 -I archive_publisher.py init 发布库目录 --settings 设定.json
python3 -I archive_publisher.py publish 发布库目录 --batch 批次.json
python3 -I archive_publisher.py current 发布库目录   # 读者入口：当前版本与文件路径
python3 -I archive_publisher.py status  发布库目录   # 当前版本与现行卷名册
```

退出码：`0` 正常；`1` 读写/解析失败；`2` 批次或材料无效（过期基版、
无效分卷、同批重复操作同一卷号、未知卷号等）；`3` 已有发布进程在进行。

## 案卷设定（init 时固定，之后只读）

```jsonc
{
  "history": {"lo": 0, "hi": 1000000000000},
  "keys": ["balance", "owner", "risk_flag", "memo"],
  "groups": {                            // 互不重叠且覆盖名册的保管组
    "grp-account": ["balance", "risk_flag"],
    "grp-profile": ["owner", "memo"]
  },
  "snapshot": { ... },                   // 可选：现有格式终态快照
  "checks": [ ... ]                      // 可选：现有格式人工核对单
}
```

快照与核对单作为**独立材料原样保留**进每一版案卷（来源清单标
`"origin": "settings"`）；核对单 id 不得使用保留前缀 `log:`。

## 分卷格式

```jsonc
{
  "volume_id": "acct-2024-w1",           // 唯一卷号
  "group": "grp-account",                // 所属保管组
  "range": {"a": 1, "b": 600},           // 受覆盖的变更边界半开区间：
                                         // 覆盖边界 a..b-1，须 lo < a < b <= hi
  "writes": [
    {"position": 500, "key": "balance", "before": 1000, "after": 2500}
  ]
}
```

- 分卷只覆盖所声明组内的键和案卷内部边界；范围内清单未列出的写即
  “没发生”，范围外不作证。
- 同卷同边界同键至多一条写；before/after 至少给一侧；明确 `null`
  是提供的值，不是未提供。

## 批次格式与发布流程

```jsonc
{
  "base": 1,                             // 基版：本批次基于哪一版（首批基于 v0 空名册）
  "changes": [
    {"op": "add",      "volume": { ... }},
    {"op": "replace",  "volume_id": "acct-2024-w1", "volume": { ... }},
    {"op": "withdraw", "volume_id": "acct-2024-w2"}
  ]
}
```

交接员先用 `current`/`status` 查到当前版本号，把它填进 `base` 再提交。
整批先校验后落盘：过期基版、任何无效材料、同一批重复操作同一卷号都会
**整批拒绝**（退出码 2），不接受部分变动；换卷前后的范围都按现行材料
重新判定。一次只支持一名发布者（`.lock` 排他，冲突退出码 3）。

## 合成规则（逐边界逐键，只看覆盖它的现行分卷）

| 覆盖情况 | 结果 |
| --- | --- |
| 无覆盖 | 缺段，来源清单记 `reason: "no_coverage"` |
| 有覆盖且都未列写 | 边界保持连续，不产生材料 |
| 有卷列写且有卷在其覆盖内未列写；或各卷同侧值相矛盾 | 只隔离该键该边界：缺段，`reason: "dispute"`，争议写及其部分值不交给查询端 |
| 否则 | 合成一条精确写：不同卷可提供互补前后侧值，都未提供的一侧缺省 |

来源清单（`provenance.json`）与案卷材料 id 一一对应：

- 精确写 → `sources`：采信的分卷及各自提供的侧值；
- 分歧缺段 → `claims`：各覆盖卷 `claim: "write"`（附列出的侧值）或
  `claim: "unlisted"`，另标 `cause`（`listed_and_unlisted` /
  `conflicting_side_values`）；
- 独立快照、核对单与其他键不因某处分歧作废。

## 版本一致性与读者约定

- 现行卷名册、案卷、来源清单作为同一版发布在 `releases/v<N>/`
  （`archive.json` / `provenance.json` / `meta.json`），发布后不再改动。
- `CURRENT` 指针原子切换；无效批次或发布进程中途被终止都不会暴露半版
  （残留的 `.tmp-*` 从不被引用，下次发布时清理）。
- **读者**：读 `current` 输出的版本号与路径（或自行读 `CURRENT` 文件），
  然后打开**同一版**目录下的案卷与来源清单；旧版在读者持有期间保持
  不变，不会读到混版。查询仍用现有入口：

  ```bash
  python3 -I forensic_query.py "$(python3 -I archive_publisher.py current 发布库目录 | jq -r .archive)" -q 查询.json
  ```

## 增量与稀疏

- 按组归并：只更动部分保管组的批次**不重新读取或归并未变组的原始分卷**，
  直接复用 `fragments/` 里已有的整理结果重新组合（发布摘要中的
  `merged_groups` / `reused_groups` 可验证）。
- 区间扫描 + 二分，不逐位置展开，也不为覆盖变化遍历组内全键
  （生成案卷格式本身要求的键清单除外）；10¹² 跨度已验证。

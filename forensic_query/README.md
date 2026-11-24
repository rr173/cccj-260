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

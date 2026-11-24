#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地取证查询工具（只读，不回写快照，不补造缺失交易）。

模型
----
案卷声明一段历史（位置半开区间 [lo, hi)，即历史位置 lo..hi-1）。
位置 p 的“变更”指从状态 p-1 到状态 p，因此精确写/缺段挂在边界 p 上，
阻断 p-1 与 p 之间的连续性。

材料三类：
  * snapshot  终态字段快照（位于 hi-1 或材料自带 position 的点实据）
  * checks    人工核对单（点实据：position/key/value，value 允许为 null）
  * writes    完备日志中的精确写（position/key/before?/after?）
              before 约束 position-1，after 约束 position；
              只要列出该写，即便只给一侧，该边界也强制阻断，
              不允许把缺的一侧当成与另一侧相同。
  * gaps      缺段：range [a,b) 是受影响提交位置（边界）的半开范围，
              keys 为可能被改写的键集合，或 null 表示全体键。
              缺段范围内不允许出现针对这些键的精确写（结构无效）。

判定（逐键独立）：
  阻断边界（精确写、该键缺段、全体键缺段）之外，同一值证据可沿
  未改写边界向任意方向连续使用；阻断区间内部的位置各自孤立。
  对一次 (position, key) 查询：
    - 落在同一个可连续取值区间（或孤立位置）上的真实证据唯一一致
      -> confirmed，并给实据及该实据可适用的区间；
    - 同一区间上出现互相矛盾的真实证据 -> conflict，列出冲突材料；
    - 没有任何真实证据 -> insufficient。

材料结构无效（越界、类型错误、键未登记、缺段包住精确写等）与
业务证据冲突严格区分：前者整卷拒绝并报 structural_error，
后者在查询结论中体现。

复杂度：材料数 M、键数 K、查询数 Q。全体键缺段只存一份；
所有计算基于区间合并与二分查找，不随历史位置数量展开。
"""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# 类型工具
# --------------------------------------------------------------------------

# 允许的证据值：int（不含 bool）、str、明确空值 None
def valid_value(v: Any) -> bool:
    return v is None or isinstance(v, (str, int)) and not isinstance(v, bool)


def value_key(v: Any) -> Tuple[str, Any]:
    """用于区分值类型与判等的可哈希键。"""
    if v is None:
        return ("null", None)
    if isinstance(v, bool):  # bool 是 int 子类，结构校验应已拦掉，双保险
        return ("bool", v)
    if isinstance(v, int):
        return ("int", v)
    return ("str", v)


def display_value(v: Any) -> Any:
    return v  # JSON 原生可表达 int/str/null


class StructuralError(Exception):
    """材料结构无效（区别于业务证据冲突）。"""


# --------------------------------------------------------------------------
# 案卷加载与校验
# --------------------------------------------------------------------------

class Archive:
    def __init__(self, doc: Any):
        if not isinstance(doc, dict):
            raise StructuralError("顶层材料必须是 JSON 对象")

        hist = doc.get("history")
        if (
            not isinstance(hist, dict)
            or not isinstance(hist.get("lo"), int)
            or isinstance(hist.get("lo"), bool)
            or not isinstance(hist.get("hi"), int)
            or isinstance(hist.get("hi"), bool)
        ):
            raise StructuralError("history 必须为包含整数 lo/hi 的对象")
        self.lo, self.hi = hist["lo"], hist["hi"]
        if self.lo > self.hi:
            raise StructuralError("history.lo 不得大于 history.hi")

        keys = doc.get("keys")
        if not isinstance(keys, list) or not keys:
            raise StructuralError("keys 必须为非空字符串数组")
        if any(not isinstance(k, str) for k in keys):
            raise StructuralError("keys 必须全部为字符串")
        if len(set(keys)) != len(keys):
            raise StructuralError("keys 中存在重复键名")
        self.keys: List[str] = list(keys)
        self.key_set = set(keys)

        # key -> 点实据列表 [(position, value, 材料描述)]
        self.evidence: Dict[str, List[Tuple[int, Any, dict]]] = {k: [] for k in keys}
        # key -> 精确写边界位置（去重排序后使用）
        self.write_positions: Dict[str, set] = {k: set() for k in keys}
        # key -> 缺段区间列表（专属缺段）
        self.key_gaps: Dict[str, List[Tuple[int, int]]] = {k: [] for k in keys}
        # 全体键缺段（只存一份，不按键复制）
        self.global_gaps: List[Tuple[int, int]] = []
        # 每条精确写的完整记录，供结构校验（缺段不得包住精确写）
        self.writes_index: List[Tuple[int, str]] = []
        # 材料 id 去重
        material_ids: set = set()

        self._load_snapshot(doc.get("snapshot"))
        self._load_checks(doc.get("checks", []), material_ids)
        self._load_writes(doc.get("writes", []), material_ids)
        self._load_gaps(doc.get("gaps", []), material_ids)

        for k in self.evidence:
            self.evidence[k].sort(key=lambda e: e[0])

        # 阻断区间缓存：key -> (starts, ends, kinds)
        self._blocked_cache: Dict[str, Tuple[List[int], List[int], List[str]]] = {}
        # 组件缓存：key -> (starts, ends, kinds)，kind: "free" / "gap"
        self._component_cache: Dict[str, Tuple[List[int], List[int], List[str]]] = {}

    # ----- 各材料的结构校验 -----

    def _check_pos(self, pos: Any, what: str) -> int:
        if not isinstance(pos, int) or isinstance(pos, bool):
            raise StructuralError("%s 的 position 必须为整数" % what)
        if not (self.lo <= pos < self.hi):
            raise StructuralError(
                "%s 位置 %d 超出声明历史 [%d, %d)" % (what, pos, self.lo, self.hi)
            )
        return pos

    def _check_boundary(self, pos: Any, what: str) -> int:
        if not isinstance(pos, int) or isinstance(pos, bool):
            raise StructuralError("%s 的 position 必须为整数" % what)
        # 变更边界 p：从 p-1 到 p，合法范围 (lo, hi]
        if not (self.lo < pos <= self.hi):
            raise StructuralError(
                "%s 边界位置 %d 超出合法变更范围 (%d, %d]" % (what, pos, self.lo, self.hi)
            )
        return pos

    def _check_key(self, key: Any, what: str) -> str:
        if not isinstance(key, str):
            raise StructuralError("%s 的 key 必须为字符串" % what)
        if key not in self.key_set:
            raise StructuralError("%s 引用了未登记的键 %r" % (what, key))
        return key

    def _check_id(self, mid: Any, material_ids: set, what: str) -> str:
        if not isinstance(mid, str) or not mid:
            raise StructuralError("%s 必须带非空字符串 id" % what)
        if mid in material_ids:
            raise StructuralError("材料 id 重复: %r" % mid)
        material_ids.add(mid)
        return mid

    def _load_snapshot(self, snap: Any) -> None:
        if snap is None:
            return
        if not isinstance(snap, dict):
            raise StructuralError("snapshot 必须为对象")
        values = snap.get("values")
        if not isinstance(values, dict):
            raise StructuralError("snapshot.values 必须为键值对象")
        pos = snap.get("position", self.hi - 1)
        if self.lo == self.hi:
            raise StructuralError("声明历史为空区间，不允许提供 snapshot")
        self._check_pos(pos, "snapshot")
        for key, v in values.items():
            self._check_key(key, "snapshot")
            if not valid_value(v):
                raise StructuralError(
                    "snapshot 中键 %r 的值必须为整数、字符串或 null" % key
                )
            self.evidence[key].append(
                (
                    pos,
                    v,
                    {
                        "material_id": "terminal-snapshot",
                        "kind": "snapshot",
                        "position": pos,
                    },
                )
            )

    def _load_checks(self, checks: Any, material_ids: set) -> None:
        if not isinstance(checks, list):
            raise StructuralError("checks 必须为数组")
        for i, item in enumerate(checks):
            what = "checks[%d]" % i
            if not isinstance(item, dict):
                raise StructuralError("%s 必须为对象" % what)
            mid = self._check_id(item.get("id"), material_ids, what)
            pos = self._check_pos(item.get("position"), what)
            key = self._check_key(item.get("key"), what)
            v = item["value"] if "value" in item else _MISSING
            if v is _MISSING or not valid_value(v):
                raise StructuralError(
                    "%s 必须显式给出 value（整数、字符串或 null；缺字段不算空值）" % what
                )
            self.evidence[key].append(
                (
                    pos,
                    v,
                    {"material_id": mid, "kind": "manual_check", "position": pos},
                )
            )

    def _load_writes(self, writes: Any, material_ids: set) -> None:
        if not isinstance(writes, list):
            raise StructuralError("writes 必须为数组")
        for i, item in enumerate(writes):
            what = "writes[%d]" % i
            if not isinstance(item, dict):
                raise StructuralError("%s 必须为对象" % what)
            mid = self._check_id(item.get("id"), material_ids, what)
            pos = self._check_boundary(item.get("position"), what)
            key = self._check_key(item.get("key"), what)
            if "before" not in item and "after" not in item:
                raise StructuralError(
                    "%s 至少要给出 before 或 after 之一" % what
                )
            before = item["before"] if "before" in item else _MISSING
            after = item["after"] if "after" in item else _MISSING
            if before is not _MISSING and not valid_value(before):
                raise StructuralError("%s 的 before 值类型无效" % what)
            if after is not _MISSING and not valid_value(after):
                raise StructuralError("%s 的 after 值类型无效" % what)

            self.write_positions[key].add(pos)
            self.writes_index.append((pos, key))
            if before is not _MISSING:
                # 前值约束 p-1；p-1 必在历史位置内（pos > lo）
                self.evidence[key].append(
                    (
                        pos - 1,
                        before,
                        {
                            "material_id": mid,
                            "kind": "write_before",
                            "position": pos - 1,
                            "write_position": pos,
                        },
                    )
                )
            if after is not _MISSING:
                # 后值约束 p；p=hi 时落在历史之外，仅作阻断不作点实据
                if pos < self.hi:
                    self.evidence[key].append(
                        (
                            pos,
                            after,
                            {
                                "material_id": mid,
                                "kind": "write_after",
                                "position": pos,
                                "write_position": pos,
                            },
                        )
                    )

    def _load_gaps(self, gaps: Any, material_ids: set) -> None:
        if not isinstance(gaps, list):
            raise StructuralError("gaps 必须为数组")
        for i, item in enumerate(gaps):
            what = "gaps[%d]" % i
            if not isinstance(item, dict):
                raise StructuralError("%s 必须为对象" % what)
            mid = self._check_id(item.get("id"), material_ids, what)
            rng = item.get("range")
            if (
                not isinstance(rng, dict)
                or not isinstance(rng.get("a"), int)
                or isinstance(rng.get("a"), bool)
                or not isinstance(rng.get("b"), int)
                or isinstance(rng.get("b"), bool)
            ):
                raise StructuralError("%s.range 必须为包含整数 a/b 的对象" % what)
            a, b = rng["a"], rng["b"]
            if a >= b:
                raise StructuralError("%s.range 必须满足 a < b" % what)
            # 受影响提交位置即变更边界，合法范围 (lo, hi]
            if not (self.lo < a and b <= self.hi):
                raise StructuralError(
                    "%s 缺段范围 [%d,%d) 超出合法变更范围 (%d,%d]，"
                    "受影响范围不能延伸到案卷声明的历史之外"
                    % (what, a, b, self.lo, self.hi)
                )
            keys_field = item.get("keys")
            if keys_field is None:
                self.global_gaps.append((a, b))
                affected = None
            else:
                if not isinstance(keys_field, list) or not keys_field:
                    raise StructuralError(
                        "%s.keys 必须为非空字符串数组，或用 null 表示全体键" % what
                    )
                if any(not isinstance(k, str) for k in keys_field):
                    raise StructuralError("%s.keys 必须全部为字符串" % what)
                if len(set(keys_field)) != len(keys_field):
                    raise StructuralError("%s.keys 中存在重复键名" % what)
                affected = [self._check_key(k, what) for k in keys_field]
                for k in affected:
                    self.key_gaps[k].append((a, b))

            # 缺段内不允许存在针对这些键的精确写
            for wpos, wkey in self.writes_index:
                if a <= wpos < b and (affected is None or wkey in affected):
                    raise StructuralError(
                        "%s 缺段 [%d,%d) 包住了键 %r 在位置 %d 的精确写 %r；"
                        "缺段内不得有针对受影响键的精确写"
                        % (what, a, b, wkey, wpos, mid)
                    )

    # ----- 阻断区间与组件 -----

    @staticmethod
    def _merge_intervals(
        intervals: List[Tuple[int, int]]
    ) -> List[Tuple[int, int]]:
        if not intervals:
            return []
        intervals = sorted(intervals)
        out: List[Tuple[int, int]] = []
        ca, cb = intervals[0]
        for a, b in intervals[1:]:
            if a <= cb:  # 相邻 [1,3)+[3,5) 也合并：边界 3 两侧均被阻断
                cb = max(cb, b)
            else:
                out.append((ca, cb))
                ca, cb = a, b
        out.append((ca, cb))
        return out

    def _blocked_for(self, key: str) -> Tuple[List[int], List[int], List[str]]:
        """返回该键被阻断的边界区间（已合并），kind 标记来源。"""
        cached = self._blocked_cache.get(key)
        if cached is not None:
            return cached
        raw: List[Tuple[int, int, str]] = []
        for a, b in self.global_gaps:
            raw.append((a, b, "gap"))
        for a, b in self.key_gaps[key]:
            raw.append((a, b, "gap"))
        for p in self.write_positions[key]:
            raw.append((p, p + 1, "write"))
        raw.sort()
        starts: List[int] = []
        ends: List[int] = []
        kinds: List[str] = []
        for a, b, kind in raw:
            if starts and a <= ends[-1]:
                ends[-1] = max(ends[-1], b)
                # 合并区间里只要含缺段，组件切分上就按 gap 处理
                if kind == "gap":
                    kinds[-1] = "gap"
            else:
                starts.append(a)
                ends.append(b)
                kinds.append(kind)
        cached = (starts, ends, kinds)
        self._blocked_cache[key] = cached
        return cached

    def _components_for(
        self, key: str
    ) -> Tuple[List[int], List[int], List[str]]:
        """
        历史位置 [lo, hi) 的组件划分（隐式区间表示，不展开位置）：
          - "free" 组件 [a,b)：内部没有阻断边界，值可在组件内连续；
          - "gap"  组件 [a,b)：其中每个位置都被阻断边界包围、彼此孤立，
            查询时只有恰好落在该位置上的点实据可用，适用区间退化为单点。

        阻断边界区间 [a,b) 切断边 (a-1,a)..(b-2,b-1)；边 (b-1,b) 对应
        边界 b，不在阻断范围内，故位置 b-1 并入右侧自由组件。
        因此孤立位置范围是 [a, b-1)（可能为空，如单个精确写 [p,p+1)）。
        """
        cached = self._component_cache.get(key)
        if cached is not None:
            return cached
        b_starts, b_ends, _ = self._blocked_for(key)
        starts: List[int] = []
        ends: List[int] = []
        kinds: List[str] = []

        def add_free(a: int, b: int) -> None:
            if a < b:
                starts.append(a)
                ends.append(b)
                kinds.append("free")

        cursor = self.lo
        for a, b in zip(b_starts, b_ends):
            add_free(cursor, a)            # 阻断区间左侧的自由段
            if a < b - 1:                  # 孤立位置 [a, b-1)，整体存一个区间
                starts.append(a)
                ends.append(b - 1)
                kinds.append("gap")
            cursor = b - 1                 # 位置 b-1 经未阻断边 (b-1,b) 连向右侧
        add_free(cursor, self.hi)
        cached = (starts, ends, kinds)
        self._component_cache[key] = cached
        return cached

    def _locate_component(
        self, key: str, pos: int
    ) -> Tuple[int, int, str]:
        starts, ends, kinds = self._components_for(key)
        idx = bisect.bisect_right(starts, pos) - 1
        if idx < 0 or not (starts[idx] <= pos < ends[idx]):
            # 理论上不可达：组件覆盖全部历史位置
            raise StructuralError("内部错误：位置 %d 未落入任何组件" % pos)
        return starts[idx], ends[idx], kinds[idx]

    # ----- 查询 -----

    def evaluate(self, pos: int, key: str) -> dict:
        comp_a, comp_b, kind = self._locate_component(key, pos)
        ev = self.evidence[key]
        positions = [e[0] for e in ev]
        if kind == "gap":
            # 缺段组件内位置彼此孤立：只认恰好落在该位置上的点实据
            hit = bisect.bisect_left(positions, pos)
            on_component = (
                [ev[hit]] if hit < len(ev) and ev[hit][0] == pos else []
            )
        else:
            left = bisect.bisect_left(positions, comp_a)
            right = bisect.bisect_left(positions, comp_b)
            on_component = ev[left:right]

        if not on_component:
            return {
                "status": "insufficient",
                "position": pos,
                "key": key,
                "component": {"start": comp_a, "end": comp_b, "kind": kind},
                "evidence": [],
                "message": "该可取值区间内没有任何真实证据，且无法跨阻断边界推值",
            }

        by_value: Dict[Tuple[str, Any], List[dict]] = {}
        for epos, v, mat in on_component:
            by_value.setdefault(value_key(v), []).append(mat)

        if len(by_value) == 1:
            (_, v), mats = next(iter(by_value.items()))
            return {
                "status": "confirmed",
                "position": pos,
                "key": key,
                "value": display_value(v),
                "component": {"start": comp_a, "end": comp_b, "kind": kind},
                "evidence": mats,
                "applicability": _applicability(pos, comp_a, comp_b, kind),
            }

        return {
            "status": "conflict",
            "position": pos,
            "key": key,
            "component": {"start": comp_a, "end": comp_b, "kind": kind},
            "conflicting_evidence": [
                {"value": display_value(v), "materials": mats}
                for (_, v), mats in sorted(
                    by_value.items(), key=lambda kv: repr(kv[0][1])
                )
            ],
            "message": "相互矛盾的真实证据落在同一个可连续取值的区间",
        }


_MISSING = object()


def _applicability(pos: int, comp_a: int, comp_b: int, kind: str) -> dict:
    """实据可适用区间：free 组件即整个连续区间；孤立位置只适用于该点。"""
    if kind == "free":
        return {"start": comp_a, "end": comp_b, "half_open": True}
    return {"start": pos, "end": pos + 1, "half_open": True}


# --------------------------------------------------------------------------
# 查询批次与 CLI
# --------------------------------------------------------------------------

def _validate_query(q: Any, arch: Archive, idx: int) -> Optional[dict]:
    what = "queries[%d]" % idx
    if not isinstance(q, dict):
        return {"index": idx, "status": "invalid_query",
                "error": "%s 必须为对象" % what}
    pos, key = q.get("position"), q.get("key")
    if not isinstance(pos, int) or isinstance(pos, bool) or not (arch.lo <= pos < arch.hi):
        return {"index": idx, "status": "invalid_query",
                "error": "%s.position 必须落在声明历史 [%d,%d) 内" % (what, arch.lo, arch.hi)}
    if not isinstance(key, str) or key not in arch.key_set:
        return {"index": idx, "status": "invalid_query",
                "error": "%s.key 未在 keys 名册中登记" % what}
    return None


def run_queries(arch: Archive, queries: Any) -> List[dict]:
    if not isinstance(queries, list):
        raise StructuralError("queries 必须为数组")
    results: List[dict] = []
    for i, q in enumerate(queries):
        bad = _validate_query(q, arch, i)
        if bad is not None:
            results.append(bad)
            continue
        results.append(arch.evaluate(q["position"], q["key"]))
    return results


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="本地取证查询工具：基于字段快照、人工核对单、精确写与缺段声明，"
        "判定历史位置上字段值可确认/不足/冲突。只读，不回写任何材料。"
    )
    parser.add_argument("archive", help="案卷 JSON 文件路径")
    parser.add_argument(
        "-q", "--queries",
        help="查询批次 JSON 文件（数组，或含 queries 字段的对象）；"
             "省略时使用案卷内的 queries 字段",
    )
    parser.add_argument("-o", "--output", help="结果输出文件，省略则写到标准输出")
    args = parser.parse_args(argv)

    try:
        with open(args.archive, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"structural_error": "无法读取案卷: %s" % exc},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    try:
        arch = Archive(doc)
    except StructuralError as exc:
        print(json.dumps({"structural_error": str(exc)},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    if args.queries:
        try:
            with open(args.queries, "r", encoding="utf-8") as f:
                qdoc = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"structural_error": "无法读取查询文件: %s" % exc},
                             ensure_ascii=False, indent=2), file=sys.stderr)
            return 1
        queries = qdoc.get("queries", qdoc) if isinstance(qdoc, dict) else qdoc
    else:
        queries = doc.get("queries", [])

    try:
        results = run_queries(arch, queries)
    except StructuralError as exc:
        print(json.dumps({"structural_error": str(exc)},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    out = {
        "history": {"lo": arch.lo, "hi": arch.hi},
        "query_count": len(results),
        "results": results,
    }
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

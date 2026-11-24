# -*- coding: utf-8 -*-
"""forensic_query 的单元测试。运行：python3 -I -m unittest -v"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensic_query import Archive, StructuralError, run_queries  # noqa: E402


def base_doc():
    return {
        "history": {"lo": 0, "hi": 100},
        "keys": ["alpha", "beta", "gamma"],
        "snapshot": {"position": 99, "values": {"alpha": 7, "beta": "b9"}},
        "checks": [
            {"id": "c1", "position": 10, "key": "alpha", "value": 5},
            {"id": "c2", "position": 20, "key": "beta", "value": "x"},
            {"id": "c3", "position": 30, "key": "gamma", "value": None},
        ],
        "writes": [
            {"id": "w1", "position": 50, "key": "alpha", "before": 5, "after": 7},
            {"id": "w2", "position": 60, "key": "beta", "after": "b9"},
            {"id": "w3", "position": 70, "key": "gamma", "before": None},
        ],
        "gaps": [],
    }


def result_map(results):
    return {(r["position"], r["key"]): r for r in results}


class TestContinuity(unittest.TestCase):
    def setUp(self):
        self.arch = Archive(base_doc())

    def ask(self, pos, key):
        return self.arch.evaluate(pos, key)

    def test_value_flows_both_directions_within_free_component(self):
        # alpha：check@10=5 与写 w1 前值@49=5 同处 [0,50) 自由组件
        r = self.ask(35, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 5)
        self.assertEqual(r["applicability"], {"start": 0, "end": 50, "half_open": True})
        ids = {e["material_id"] for e in r["evidence"]}
        self.assertEqual(ids, {"c1", "w1"})

        # 写后组件 [50,100)：w1 后值@50=7 与快照@99=7
        r = self.ask(80, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 7)
        self.assertEqual(r["applicability"], {"start": 50, "end": 100, "half_open": True})

    def test_write_blocks_even_with_one_side_missing(self):
        # w2 只给 after：beta@60 起为 b9；边界 60 强制阻断，
        # 不能因为缺 before 就把 c2@20='x' 当作与 after 相同
        r = self.ask(55, "beta")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], "x")
        r = self.ask(60, "beta")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], "b9")
        r = self.ask(59, "beta")
        self.assertEqual(r["component"]["end"], 60)

    def test_explicit_null_is_evidence_missing_field_is_not(self):
        # gamma：c3@30=null，w3 before@69=null，同一自由组件 [0,70)
        r = self.ask(40, "gamma")
        self.assertEqual(r["status"], "confirmed")
        self.assertIsNone(r["value"])
        # 写后无任何证据 -> 不足（不能把 null 穿过去）
        r = self.ask(70, "gamma")
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["evidence"], [])

    def test_snapshot_at_hi_is_still_blocked_by_write_at_hi(self):
        doc = base_doc()
        doc["writes"].append(
            {"id": "w_end", "position": 100, "key": "alpha", "before": 7}
        )
        arch = Archive(doc)
        # 写在边界 100：切断的边 (99,100) 已在历史之外，历史内部组件不变；
        # before@99=7 作为点实据与快照一致，仍可确认
        r = arch.evaluate(99, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 7)
        self.assertEqual(r["component"], {"start": 50, "end": 100, "kind": "free"})
        self.assertEqual(
            arch.evaluate(98, "alpha")["component"], r["component"]
        )

    def test_conflict_within_same_component(self):
        doc = base_doc()
        doc["checks"].append(
            {"id": "c_bad", "position": 11, "key": "alpha", "value": 999}
        )
        arch = Archive(doc)
        r = arch.evaluate(35, "alpha")
        self.assertEqual(r["status"], "conflict")
        vals = {c["value"] for c in r["conflicting_evidence"]}
        self.assertEqual(vals, {5, 999})
        # 阻断另一侧不受影响
        r2 = arch.evaluate(80, "alpha")
        self.assertEqual(r2["status"], "confirmed")
        self.assertEqual(r2["value"], 7)

    def test_contradiction_across_blocked_boundary_is_not_conflict(self):
        doc = base_doc()
        # 写两侧值不同是正常的：5 vs 7，不算冲突
        r = self.ask(49, "alpha")
        self.assertEqual((r["status"], r["value"]), ("confirmed", 5))
        r = self.ask(50, "alpha")
        self.assertEqual((r["status"], r["value"]), ("confirmed", 7))


class TestGaps(unittest.TestCase):
    def test_gap_splits_components_and_inner_positions_are_isolated(self):
        doc = base_doc()
        doc["gaps"] = [
            {"id": "g1", "range": {"a": 40, "b": 45}, "keys": ["alpha"]}
        ]
        arch = Archive(doc)
        # 自由组件 [0,40)：c1=5 仍可确认
        r = arch.evaluate(39, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 5)
        # 缺段内部孤立位置 40..43 无证据 -> 不足
        for p in (40, 41, 43):
            r = arch.evaluate(p, "alpha")
            self.assertEqual(r["status"], "insufficient")
            self.assertEqual(r["component"]["kind"], "gap")
        # 位置 44 经未阻断边 (44,45) 连入右侧自由组件，w1 前值@49=5 可确认
        r = arch.evaluate(44, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 5)
        # 缺段另一侧独立证据：w1 前值@49=5 支撑 [45,50)（实际为 [44,50)）
        r = arch.evaluate(47, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 5)
        # 别的键不受影响：beta 跨同一区间连续
        r = arch.evaluate(42, "beta")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], "x")

    def test_evidence_inside_gap_is_confined_to_its_point(self):
        doc = base_doc()
        doc["gaps"] = [
            {"id": "g1", "range": {"a": 40, "b": 45}, "keys": ["alpha"]}
        ]
        doc["checks"].append(
            {"id": "c_in", "position": 42, "key": "alpha", "value": 5}
        )
        arch = Archive(doc)
        r = arch.evaluate(42, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["applicability"]["start"], 42)
        self.assertEqual(r["applicability"]["end"], 43)
        # 相邻的 41、43 不能借这条证据
        self.assertEqual(arch.evaluate(41, "alpha")["status"], "insufficient")
        self.assertEqual(arch.evaluate(43, "alpha")["status"], "insufficient")

    def test_global_gap_stored_once_and_hits_every_key(self):
        doc = base_doc()
        doc["gaps"] = [
            {"id": "g_all", "range": {"a": 80, "b": 90}, "keys": None}
        ]
        arch = Archive(doc)
        # 内部表示：全局缺段只有一份
        self.assertEqual(arch.global_gaps, [(80, 90)])
        for k in ("alpha", "beta", "gamma"):
            self.assertEqual(arch.key_gaps[k], [])
            r = arch.evaluate(85, k)
            self.assertEqual(r["status"], "insufficient")
            self.assertEqual(r["component"]["kind"], "gap")
        # 快照@99 在缺段之后，组件 [90,100) 仍成立
        r = arch.evaluate(95, "alpha")
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["value"], 7)

    def test_adjacent_gaps_merge(self):
        doc = base_doc()
        doc["gaps"] = [
            {"id": "g1", "range": {"a": 40, "b": 42}, "keys": ["alpha"]},
            {"id": "g2", "range": {"a": 42, "b": 45}, "keys": ["alpha"]},
        ]
        arch = Archive(doc)
        starts, ends, _ = arch._blocked_for("alpha")
        # 两个相邻缺段合并为 [40,45)；基线中 w1 的精确写边界 50 独立保留
        self.assertEqual(list(zip(starts, ends)), [(40, 45), (50, 51)])


class TestSparseLargeRanges(unittest.TestCase):
    def test_huge_positions_no_expansion(self):
        huge = 10 ** 12
        doc = {
            "history": {"lo": 0, "hi": huge},
            "keys": ["k"],
            "snapshot": {"position": huge - 1, "values": {"k": 1}},
            "checks": [{"id": "c", "position": 0, "key": "k", "value": 1}],
            "writes": [
                {"id": "w", "position": huge // 2, "key": "k",
                 "before": 1, "after": 1}
            ],
            "gaps": [
                {"id": "g", "range": {"a": huge - 100, "b": huge - 50},
                 "keys": None}
            ],
        }
        arch = Archive(doc)  # 构造不随 huge 展开
        r = arch.evaluate(huge // 3, "k")
        self.assertEqual((r["status"], r["value"]), ("confirmed", 1))
        r = arch.evaluate(huge - 80, "k")
        self.assertEqual(r["status"], "insufficient")  # 全局缺段孤立点
        r = arch.evaluate(huge - 1, "k")
        self.assertEqual(r["status"], "confirmed")  # 快照独立支撑
        # 组件数量是常数级
        starts, ends, kinds = arch._components_for("k")
        self.assertLessEqual(len(starts), 6)


class TestStructuralErrors(unittest.TestCase):
    def assert_bad(self, mutate, needle):
        doc = base_doc()
        mutate(doc)
        with self.assertRaises(StructuralError) as ctx:
            Archive(doc)
        self.assertIn(needle, str(ctx.exception))

    def test_out_of_range_gap(self):
        self.assert_bad(
            lambda d: d["gaps"].append(
                {"id": "gx", "range": {"a": 0, "b": 5}, "keys": ["alpha"]}
            ),
            "超出合法变更范围",
        )
        self.assert_bad(
            lambda d: d["gaps"].append(
                {"id": "gx", "range": {"a": 90, "b": 101}, "keys": None}
            ),
            "历史之外",
        )

    def test_gap_wrapping_precise_write_is_structural(self):
        self.assert_bad(
            lambda d: d["gaps"].append(
                {"id": "gx", "range": {"a": 48, "b": 52}, "keys": ["alpha"]}
            ),
            "包住了键",
        )
        # 全体键缺段同样适用
        self.assert_bad(
            lambda d: d["gaps"].append(
                {"id": "gx", "range": {"a": 48, "b": 52}, "keys": None}
            ),
            "包住了键",
        )

    def test_unknown_key_bad_type_duplicate_id(self):
        self.assert_bad(
            lambda d: d["checks"].append(
                {"id": "c9", "position": 1, "key": "nope", "value": 1}
            ),
            "未登记的键",
        )
        self.assert_bad(
            lambda d: d["checks"].append(
                {"id": "c1", "position": 1, "key": "alpha", "value": 1}
            ),
            "材料 id 重复",
        )
        self.assert_bad(
            lambda d: d["checks"].append(
                {"id": "c9", "position": 1, "key": "alpha", "value": True}
            ),
            "value",
        )

    def test_missing_value_field_is_not_null(self):
        doc = base_doc()
        doc["checks"].append({"id": "c9", "position": 1, "key": "alpha"})
        with self.assertRaises(StructuralError):
            Archive(doc)

    def test_write_without_any_side(self):
        doc = base_doc()
        doc["writes"].append({"id": "w9", "position": 55, "key": "alpha"})
        with self.assertRaises(StructuralError):
            Archive(doc)


class TestQueriesAndCLI(unittest.TestCase):
    def test_invalid_query_is_reported_not_fatal(self):
        arch = Archive(base_doc())
        results = run_queries(arch, [
            {"position": 5, "key": "alpha"},
            {"position": 1000, "key": "alpha"},
            {"position": 5, "key": "nope"},
            "not an object",
        ])
        self.assertEqual(results[0]["status"], "confirmed")
        for r in results[1:]:
            self.assertEqual(r["status"], "invalid_query")

    def test_cli_end_to_end(self):
        root = Path(__file__).resolve().parent.parent
        doc = base_doc()
        doc["queries"] = [
            {"position": 35, "key": "alpha"},
            {"position": 70, "key": "gamma"},
            {"position": 42, "key": "beta"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            arc = Path(tmp) / "case.json"
            arc.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-I", str(root / "forensic_query.py"), str(arc)],
                capture_output=True, text=True, check=True,
            )
        out = json.loads(proc.stdout)
        rm = result_map(out["results"])
        self.assertEqual(rm[(35, "alpha")]["value"], 5)
        self.assertEqual(rm[(70, "gamma")]["status"], "insufficient")
        self.assertEqual(rm[(42, "beta")]["value"], "x")

    def test_cli_structural_error_exit_code(self):
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"history": {"lo": 1, "hi": 0},
                                       "keys": ["k"]}), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-I", str(root / "forensic_query.py"), str(bad)],
                capture_output=True, text=True,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("structural_error", proc.stderr)


if __name__ == "__main__":
    unittest.main()

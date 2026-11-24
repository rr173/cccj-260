# -*- coding: utf-8 -*-
"""version_compare 的单元测试。运行：python3 -I -m unittest -v"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import archive_publisher as ap  # noqa: E402
import version_compare as vc  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def make_settings():
    return {
        "history": {"lo": 0, "hi": 1000},
        "keys": ["balance", "owner"],
        "groups": {"g-bal": ["balance"], "g-own": ["owner"]},
        "snapshot": {"position": 999,
                     "values": {"balance": 4200, "owner": "alice"}},
        "checks": [
            {"id": "chk-bal", "position": 100, "key": "balance", "value": 1000},
            {"id": "chk-own", "position": 300, "key": "owner", "value": "alice"},
        ],
    }


def vol(vid, group, a, b, writes):
    return {"volume_id": vid, "group": group,
            "range": {"a": a, "b": b}, "writes": writes}


def op_add(v):
    return {"op": "add", "volume": v}


def op_replace(vid, v):
    return {"op": "replace", "volume_id": vid, "volume": v}


def op_withdraw(vid):
    return {"op": "withdraw", "volume_id": vid}


class CompareCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = os.path.join(self.tmp.name, "store")
        self.settings_path = os.path.join(self.tmp.name, "settings.json")
        with open(self.settings_path, "w", encoding="utf-8") as f:
            json.dump(make_settings(), f)
        ap.cmd_init(self.store, self.settings_path)

    def write_batch(self, batch):
        path = os.path.join(self.tmp.name, "batch-%d.json" % os.getpid())
        with open(path, "w", encoding="utf-8") as f:
            json.dump(batch, f)
        return path

    def publish(self, batch):
        return ap.cmd_publish(self.store, self.write_batch(batch))

    def release_paths(self, version):
        rel = os.path.join(self.store, "releases", "v%d" % version)
        return (os.path.join(rel, "archive.json"),
                os.path.join(rel, "provenance.json"))

    def load_view(self, version):
        apath, ppath = self.release_paths(version)
        with open(apath, encoding="utf-8") as f:
            doc = json.load(f)
        with open(ppath, encoding="utf-8") as f:
            prov = json.load(f)
        return vc.VersionView(doc, prov, "v%d" % version)

    def compare_store(self, va, vb):
        return vc.cmd_compare_store(self.store, va, vb)

    def changes_on(self, key, result):
        return [(c["range"]["start"], c["range"]["end"],
                 c["from"]["status"], c["to"]["status"])
                for c in result["changes"] if c["key"] == key]

    def spot_check(self, va, vb, result):
        """不变式：抽样逐位置查询，与区间比较结论一致。"""
        view_a = self.load_view(va)
        view_b = self.load_view(vb)
        lo = result["scope"]["history"]["lo"]
        hi = result["scope"]["history"]["hi"]
        keys = result["scope"]["keys"]
        # 取所有分段边界作抽样点（材料数很少，点很少）
        points = {lo, hi - 1}
        for c in result["changes"]:
            points.add(c["range"]["start"])
            points.add(c["range"]["end"] - 1)
        # 再加各版组件边界
        for v in (view_a, view_b):
            for k in keys:
                s, e, _ = v.arch._components_for(k)
                for p in list(s) + [x - 1 for x in e]:
                    if lo <= p < hi:
                        points.add(p)
        for p in points:
            for k in keys:
                ca = view_a.conclusion_at(k, p)
                cb = view_b.conclusion_at(k, p)
                sig_same = vc._canonical(ca) == vc._canonical(cb)
                listed = any(
                    c["key"] == k and c["range"]["start"] <= p < c["range"]["end"]
                    for c in result["changes"]
                )
                self.assertEqual(
                    sig_same, not listed,
                    "位置 %d 键 %r：比较结果 %s 与抽样查询不一致"
                    % (p, k, "有变化" if listed else "无变化"),
                )


class TestCoreComparisons(CompareCase):
    def test_identical_versions_have_no_changes(self):
        batch = {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
            op_add(vol("C", "g-own", 100, 900, [
                {"position": 700, "key": "owner", "after": "alice"}])),
        ]}
        self.publish(batch)
        result = self.compare_store(1, 1)
        self.assertEqual(result["change_count"], 0)
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["scope"]["history"], {"lo": 0, "hi": 1000})
        self.assertEqual(result["scope"]["keys"], ["balance", "owner"])
        self.spot_check(1, 1, result)

    def test_value_change_confirmed_to_insufficient(self):
        # v1：balance@900 写 after=4200（与快照一致）；
        # v2：审计卷把 after 换成 4300（同边界同键两侧值矛盾 -> 该写变分歧，
        #     边界 900 退化为缺段），900 起的确认值丢失。
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 800, 950, [
                {"position": 900, "key": "balance",
                 "before": 2500, "after": 4200}])),
        ]})
        self.publish({"base": 1, "changes": [
            op_add(vol("B", "g-bal", 850, 950, [
                {"position": 900, "key": "balance",
                 "before": 2500, "after": 4300}])),
        ]})
        result = self.compare_store(1, 2)
        statuses = self.changes_on("balance", result)
        # v2 审计卷只覆盖到 950：900..949 分歧隔离（孤立）；
        # 950 起无覆盖缺段接续，位置 950..998 同样无实据。
        # v1 在 900 起确认 4200（写后值与快照一致）。
        self.assertIn((900, 950, "confirmed", "insufficient"), statuses)
        c = next(c for c in result["changes"]
                 if c["key"] == "balance" and c["range"]["start"] == 900)
        self.assertEqual(c["from"]["value"], 4200)
        self.assertEqual(c["to"]["status"], "insufficient")
        self.assertEqual(c["to"]["reason"], vc.INS_DISPUTE)
        # 变化前结论保留了能解释它的材料来源
        ids = {e["material_id"] for e in c["from"]["evidence"]}
        self.assertIn("log:w:900:balance", ids)
        self.spot_check(1, 2, result)

    def test_conflict_status_is_a_distinct_conclusion(self):
        # v1：同一自由组件内两条矛盾实据 -> conflict；
        # v2：纠正写值 -> confirmed。冲突作为独立状态必须被列出。
        common = {
            "history": {"lo": 0, "hi": 1000},
            "keys": ["balance"],
            "snapshot": {"position": 999, "values": {"balance": 4200}},
        }
        a = dict(common, writes=[
            {"id": "w900", "position": 900, "key": "balance",
             "before": 2500, "after": 4300}], gaps=[])
        b = dict(common, writes=[
            {"id": "w900", "position": 900, "key": "balance",
             "before": 2500, "after": 4200}], gaps=[])
        pa = os.path.join(self.tmp.name, "conf-a.json")
        pb = os.path.join(self.tmp.name, "conf-b.json")
        with open(pa, "w", encoding="utf-8") as f:
            json.dump(a, f)
        with open(pb, "w", encoding="utf-8") as f:
            json.dump(b, f)
        result = vc.cmd_compare_files(pa, pb, None, None)
        c = next(c for c in result["changes"]
                 if c["range"]["start"] <= 950 < c["range"]["end"])
        self.assertEqual(c["from"]["status"], "conflict")
        self.assertEqual(c["to"]["status"], "confirmed")
        self.assertEqual(c["to"]["value"], 4200)
        vals = {x["value"] for x in c["from"]["conflicting_evidence"]}
        self.assertEqual(vals, {4200, 4300})

    def test_insufficient_reasons_no_coverage_dispute_lack(self):
        # v0 全区间无覆盖：孤立点 -> no_coverage
        # v1：A 列写 500，B 覆盖 500 但未列写 -> dispute；
        #     另一个干净写 owner@700；balance 在写间自由段无证据 -> lack
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
            op_add(vol("B", "g-bal", 400, 900, [])),
            op_add(vol("C", "g-own", 100, 900, [
                {"position": 700, "key": "owner", "after": "alice"}])),
        ]})
        v0 = self.load_view(0)
        v1 = self.load_view(1)

        # v0 的孤立位置：无覆盖
        r = v0.conclusion_at("balance", 500)
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["reason"], vc.INS_NO_COVERAGE)
        self.assertTrue(r["basis_materials"])
        self.assertEqual(r["basis_materials"][0]["reason"], "no_coverage")

        # v1 边界 500 变分歧：自由组件内无实据 -> dispute
        r = v1.conclusion_at("balance", 600)
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["reason"], vc.INS_DISPUTE)
        gap_basis = [b for b in r["basis_materials"]
                     if b.get("reason") == "dispute"]
        self.assertTrue(gap_basis)
        # 分歧材料保留各卷主张
        claims = gap_basis[0]["provenance"]["claims"]
        self.assertEqual({c["volume_id"]: c["claim"]
                          for c in claims}, {"A": "write", "B": "unlisted"})

        # 直接用单元方式验证 lack：只有只给前值的写阻断、写后自由组件无任何
        # 点实据（且不与任何缺段相邻）
        clean_doc = {
            "history": {"lo": 0, "hi": 1000}, "keys": ["balance"],
            "writes": [{"id": "w1", "position": 500, "key": "balance",
                        "before": 1}],
            "gaps": [],
        }
        clean_view = vc.VersionView(clean_doc, None, "clean")
        r = clean_view.conclusion_at("balance", 600)
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["reason"], vc.INS_LACK)
        self.assertEqual(r["basis_materials"], [])

        result = self.compare_store(0, 1)
        self.spot_check(0, 1, result)
        # 至少存在 no_coverage -> dispute 的变化
        reasons = {
            (c["from"].get("reason"), c["to"].get("reason"))
            for c in result["changes"]
            if c["from"]["status"] == "insufficient"
        }
        self.assertIn((vc.INS_NO_COVERAGE, vc.INS_DISPUTE), reasons)

    def test_same_value_different_sources_is_listed(self):
        # v1：500 的写只来自 A（A 给双侧）；v2：加入 B（只给 after 2500），
        # 值不变但来源实据集合变化，必须列出
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
        ]})
        self.publish({"base": 1, "changes": [
            op_add(vol("B", "g-bal", 400, 900, [
                {"position": 500, "key": "balance", "after": 2500}])),
        ]})
        result = self.compare_store(1, 2)
        changed_ranges = self.changes_on("balance", result)
        # 位置 500..899：同值 2500，但 v2 实据多了来源 B
        self.assertTrue(any(
            a <= 500 and b > 500 and f == "confirmed" and t == "confirmed"
            for a, b, f, t in changed_ranges
        ))
        c = next(c for c in result["changes"]
                 if c["key"] == "balance"
                 and c["range"]["start"] <= 500 < c["range"]["end"])
        self.assertEqual(c["from"]["value"], c["to"]["value"])
        # 同一条合成写，两版的实据材料 id 相同，但来源分卷集合不同：
        # v1 仅 A，v2 为 A+B（依据变化因此整段被列出）
        self.assertEqual(
            {e["material_id"] for e in c["from"]["evidence"]},
            {e["material_id"] for e in c["to"]["evidence"]},
        )
        srcs_from = {
            s["volume_id"]
            for e in c["from"]["evidence"]
            for s in e["provenance"]["sources"]
        }
        srcs_to = {
            s["volume_id"]
            for e in c["to"]["evidence"]
            for s in e["provenance"]["sources"]
        }
        self.assertEqual(srcs_from, {"A"})
        self.assertEqual(srcs_to, {"A", "B"})
        self.spot_check(1, 2, result)

    def test_applicability_range_change_is_listed(self):
        # v1：balance 写在 500；v2 增加写在 250（值都为 1000 -> 2500 链），
        # 位置 100..249 同值 1000，但可连续范围（组件/适用区间）缩小 -> 列出
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
        ]})
        self.publish({"base": 1, "changes": [
            op_add(vol("B", "g-bal", 100, 400, [
                {"position": 250, "key": "balance",
                 "before": 1000, "after": 1000}])),
        ]})
        result = self.compare_store(1, 2)
        c = next(c for c in result["changes"]
                 if c["key"] == "balance"
                 and c["range"]["start"] <= 150 < c["range"]["end"])
        self.assertEqual(c["from"]["value"], c["to"]["value"])
        self.assertNotEqual(c["from"]["applicability"], c["to"]["applicability"])
        self.spot_check(1, 2, result)

    def test_adjacent_equal_changes_are_merged(self):
        # 同一缺段内部相邻的无证据小段：成因与依据完全相同，应合并为一个范围
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 900, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
        ]})
        result = self.compare_store(0, 1)
        # v0 缺口 [1,1000) 是单一合并缺口，内部无分段点 -> 每个键至多一条
        # 覆盖大段的变化（内部不会碎成单点列表）
        bal = [c for c in result["changes"] if c["key"] == "balance"]
        big = [c for c in bal if c["range"]["end"] - c["range"]["start"] > 100]
        self.assertTrue(big)
        # 合并后的相邻条目首尾相接但签名不同，不存在可继续合并的对
        for c1, c2 in zip(bal, bal[1:]):
            self.assertFalse(
                c1["range"]["end"] == c2["range"]["start"]
                and vc._canonical(c1["from"]) == vc._canonical(c2["from"])
                and vc._canonical(c1["to"]) == vc._canonical(c2["to"])
            )
        self.spot_check(0, 1, result)

    def test_explicit_null_change_is_detected(self):
        # 明确 null 也是可确认值：null -> 具体值的变化必须被识别
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance", "after": None}])),
        ]})
        self.publish({"base": 1, "changes": [
            op_replace("A", vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance", "after": 2500}])),
        ]})
        result = self.compare_store(1, 2)
        c = next(c for c in result["changes"]
                 if c["key"] == "balance"
                 and c["range"]["start"] <= 550 < c["range"]["end"])
        self.assertIsNone(c["from"]["value"])
        self.assertEqual(c["to"]["value"], 2500)
        self.spot_check(1, 2, result)

    def test_withdraw_restores_prior_conclusion(self):
        # v2 加入审计修正卷（900 after 4300，与 4200 冲突）；v3 撤回 ->
        # v3 对 v1 应当零变化（结论与依据完全恢复）
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 950, [
                {"position": 900, "key": "balance",
                 "before": 2500, "after": 4200}])),
        ]})
        self.publish({"base": 1, "changes": [
            op_add(vol("FIX", "g-bal", 800, 950, [
                {"position": 900, "key": "balance",
                 "before": 2500, "after": 4300}])),
        ]})
        self.publish({"base": 2, "changes": [op_withdraw("FIX")]})
        result = self.compare_store(1, 3)
        self.assertEqual(result["change_count"], 0)
        # 而 v1 -> v2 确实有变化
        result12 = self.compare_store(1, 2)
        self.assertGreater(result12["change_count"], 0)
        self.spot_check(1, 2, result12)


class TestScopeAndModes(CompareCase):
    def test_common_history_and_roster_are_reported(self):
        # 用 files 模式比较两个不同 history/keys 的案卷
        a = {
            "history": {"lo": 0, "hi": 100},
            "keys": ["k1", "k2"],
            "checks": [{"id": "c1", "position": 10, "key": "k1", "value": 1}],
            "writes": [], "gaps": [],
        }
        b = {
            "history": {"lo": 20, "hi": 120},
            "keys": ["k1", "k3"],
            "checks": [{"id": "c1", "position": 30, "key": "k1", "value": 2}],
            "writes": [],
            "gaps": [{"id": "gx", "range": {"a": 60, "b": 70},
                      "keys": ["k3"]}],
        }
        pa = os.path.join(self.tmp.name, "a.json")
        pb = os.path.join(self.tmp.name, "b.json")
        with open(pa, "w", encoding="utf-8") as f:
            json.dump(a, f)
        with open(pb, "w", encoding="utf-8") as f:
            json.dump(b, f)
        result = vc.cmd_compare_files(pa, pb, None, None)
        self.assertEqual(result["scope"]["history"], {"lo": 20, "hi": 100})
        self.assertEqual(result["scope"]["keys"], ["k1"])
        self.assertEqual(
            result["scope"]["excluded"]["positions"]["from_only"], [[0, 20]])
        self.assertEqual(
            result["scope"]["excluded"]["positions"]["to_only"], [[100, 120]])
        self.assertEqual(
            result["scope"]["excluded"]["keys"],
            {"from_only": ["k2"], "to_only": ["k3"]})
        # 无来源清单时，缺段孤立点按无覆盖兜底分类
        r = vc.VersionView(b, None, "b").conclusion_at("k3", 65)
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["reason"], vc.INS_NO_COVERAGE)
        # 自由组件无实据且不邻接任何缺段 -> lack
        r = vc.VersionView(b, None, "b").conclusion_at("k3", 40)
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["reason"], vc.INS_LACK)

    def test_no_common_history_rejected(self):
        a = {"history": {"lo": 0, "hi": 10}, "keys": ["k"],
             "writes": [], "gaps": []}
        b = {"history": {"lo": 10, "hi": 20}, "keys": ["k"],
             "writes": [], "gaps": []}
        pa = os.path.join(self.tmp.name, "a.json")
        pb = os.path.join(self.tmp.name, "b.json")
        with open(pa, "w") as f:
            json.dump(a, f)
        with open(pb, "w") as f:
            json.dump(b, f)
        with self.assertRaises(vc.CompareError):
            vc.cmd_compare_files(pa, pb, None, None)

    def test_no_common_keys_rejected(self):
        a = {"history": {"lo": 0, "hi": 100}, "keys": ["x"],
             "writes": [], "gaps": []}
        b = {"history": {"lo": 0, "hi": 100}, "keys": ["y"],
             "writes": [], "gaps": []}
        pa = os.path.join(self.tmp.name, "a.json")
        pb = os.path.join(self.tmp.name, "b.json")
        with open(pa, "w") as f:
            json.dump(a, f)
        with open(pb, "w") as f:
            json.dump(b, f)
        with self.assertRaises(vc.CompareError):
            vc.cmd_compare_files(pa, pb, None, None)

    def test_missing_version_rejected(self):
        with self.assertRaises(vc.CompareError):
            self.compare_store(0, 99)

    def test_version_identity_is_in_output(self):
        self.publish({"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance", "after": 2500}]))]})
        result = self.compare_store(0, 1)
        va, vb = result["versions"]["from"], result["versions"]["to"]
        self.assertEqual((va["version"], vb["version"]), (0, 1))
        self.assertEqual(os.path.abspath(self.store), va["store"])
        self.assertTrue(va["archive"].endswith("releases/v0/archive.json"))
        self.assertTrue(vb["provenance"].endswith("releases/v1/provenance.json"))
        self.assertEqual(len(va["archive_sha256"]), 64)
        self.assertEqual(len(vb["provenance_sha256"]), 64)


class TestSparse(unittest.TestCase):
    def test_huge_history_no_expansion(self):
        huge = 10 ** 12
        settings = {
            "history": {"lo": 0, "hi": huge},
            "keys": ["k1", "k2"],
            "groups": {"g1": ["k1"], "g2": ["k2"]},
            "snapshot": {"values": {"k1": 1, "k2": "s"}},
        }
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        sp = os.path.join(tmp.name, "settings.json")
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(settings, f)
        store = os.path.join(tmp.name, "store")
        ap.cmd_init(store, sp)
        batch = {"base": 0, "changes": [
            op_add(vol("V1", "g1", 2, huge // 2, [
                {"position": huge // 4, "key": "k1",
                 "before": 0, "after": 1}])),
        ]}
        bp = os.path.join(tmp.name, "batch.json")
        with open(bp, "w", encoding="utf-8") as f:
            json.dump(batch, f)
        ap.cmd_publish(store, bp)
        result = vc.cmd_compare_store(store, 0, 1)
        # 变化条目数是材料/键的常数级，绝不随跨度展开
        self.assertLess(len(result["changes"]), 20)
        # 覆盖 10¹² 量级的范围以区间表达
        spans = [c["range"]["end"] - c["range"]["start"]
                 for c in result["changes"]]
        self.assertTrue(any(s > huge // 10 for s in spans))
        # 抽样远端位置
        apath, ppath = None, None
        rel = os.path.join(store, "releases", "v1")
        with open(os.path.join(rel, "archive.json"), encoding="utf-8") as f:
            doc = json.load(f)
        with open(os.path.join(rel, "provenance.json"), encoding="utf-8") as f:
            prov = json.load(f)
        view = vc.VersionView(doc, prov, "v1")
        r = view.conclusion_at("k1", huge - 2)
        self.assertEqual(r["status"], "insufficient")
        self.assertEqual(r["reason"], vc.INS_NO_COVERAGE)


class TestExhaustiveEquivalence(unittest.TestCase):
    """小历史逐位置穷举：区间比较结果必须与逐点 evaluate 完全等价。"""

    def _view(self, doc):
        return vc.VersionView(doc, None, "t")

    def _brute_force_signatures(self, view, lo, hi, key):
        return [vc._canonical(view.conclusion_at(key, p))
                for p in range(lo, hi)]

    def _assert_equivalent(self, doc_a, doc_b, lo, hi, keys):
        va, vb = self._view(doc_a), self._view(doc_b)
        result = vc.compare_views(va, vb)
        # 逐位置真值
        for key in keys:
            sig_a = self._brute_force_signatures(va, lo, hi, key)
            sig_b = self._brute_force_signatures(vb, lo, hi, key)
            expected = {
                p for p in range(lo, hi) if sig_a[p - lo] != sig_b[p - lo]
            }
            listed = set()
            key_changes = [c for c in result["changes"] if c["key"] == key]
            for c in key_changes:
                s, e = c["range"]["start"], c["range"]["end"]
                # 变化段内逐位置与结论对象一致
                for p in range(s, e):
                    listed.add(p)
                    self.assertEqual(
                        vc._canonical(c["from"]), sig_a[p - lo])
                    self.assertEqual(
                        vc._canonical(c["to"]), sig_b[p - lo])
            self.assertEqual(listed, expected, "键 %r 变化位置集合不一致" % key)
            # 相邻变化段不得可继续合并（相邻且两侧签名均相同）
            for c1, c2 in zip(key_changes, key_changes[1:]):
                self.assertFalse(
                    c1["range"]["end"] == c2["range"]["start"]
                    and vc._canonical(c1["from"]) == vc._canonical(c2["from"])
                    and vc._canonical(c1["to"]) == vc._canonical(c2["to"])
                )
            # 段互不重叠且按序
            ends = [c["range"]["end"] for c in key_changes]
            starts = [c["range"]["start"] for c in key_changes]
            self.assertEqual(starts, sorted(starts))
            self.assertTrue(all(e1 <= s2 for e1, s2 in zip(ends, ends[1:])))
        return result

    def test_mixed_materials_exhaustive(self):
        # 含自由段、精确写阻断、键专属缺段、全体缺段、核对单、明确 null
        doc_a = {
            "history": {"lo": 0, "hi": 60},
            "keys": ["k1", "k2"],
            "snapshot": {"position": 59, "values": {"k1": 9}},
            "checks": [
                {"id": "c1", "position": 5, "key": "k1", "value": 1},
                {"id": "c2", "position": 8, "key": "k2", "value": None},
            ],
            "writes": [
                {"id": "w1", "position": 20, "key": "k1",
                 "before": 1, "after": 2},
                {"id": "w2", "position": 40, "key": "k2", "after": "x"},
            ],
            "gaps": [
                {"id": "g1", "range": {"a": 25, "b": 30}, "keys": ["k1"]},
                {"id": "g2", "range": {"a": 45, "b": 48}, "keys": None},
            ],
        }
        doc_b = json.loads(json.dumps(doc_a))
        # 改值、改阻断位置、改缺段范围、增删点实据
        doc_b["writes"][0]["after"] = 3
        doc_b["writes"].append(
            {"id": "w3", "position": 12, "key": "k1", "after": 1})
        doc_b["gaps"][0]["range"] = {"a": 27, "b": 32}
        doc_b["checks"].append(
            {"id": "c3", "position": 26, "key": "k1", "value": 7})
        self._assert_equivalent(doc_a, doc_b, 0, 60, ["k1", "k2"])

    def test_conflict_and_dispute_like_gaps_exhaustive(self):
        doc_a = {
            "history": {"lo": 0, "hi": 40},
            "keys": ["k1"],
            "checks": [
                {"id": "c1", "position": 5, "key": "k1", "value": 1},
                {"id": "c2", "position": 6, "key": "k1", "value": 2},
            ],
            "writes": [{"id": "w1", "position": 30, "key": "k1",
                        "before": 1, "after": 2}],
            "gaps": [{"id": "g1", "range": {"a": 15, "b": 20},
                      "keys": ["k1"]}],
        }
        doc_b = json.loads(json.dumps(doc_a))
        del doc_b["checks"][1]  # 冲突解除
        doc_b["gaps"][0]["range"] = {"a": 15, "b": 18}
        self._assert_equivalent(doc_a, doc_b, 0, 40, ["k1"])

    def test_overlapping_common_window_exhaustive(self):
        doc_a = {"history": {"lo": 0, "hi": 50}, "keys": ["k1", "kx"],
                 "checks": [{"id": "c1", "position": 10, "key": "k1",
                             "value": 1}],
                 "writes": [], "gaps": []}
        doc_b = {"history": {"lo": 20, "hi": 70}, "keys": ["k1", "ky"],
                 "checks": [{"id": "c1", "position": 30, "key": "k1",
                             "value": 2}],
                 "writes": [], "gaps": []}
        result = self._assert_equivalent(doc_a, doc_b, 20, 50, ["k1"])
        self.assertEqual(result["scope"]["history"], {"lo": 20, "hi": 50})


class TestCLI(unittest.TestCase):
    def test_store_cli_end_to_end(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = os.path.join(tmp.name, "store")
        sp = os.path.join(tmp.name, "settings.json")
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(make_settings(), f)
        ap.cmd_init(store, sp)
        bp = os.path.join(tmp.name, "b.json")
        with open(bp, "w", encoding="utf-8") as f:
            json.dump({"base": 0, "changes": [
                op_add(vol("A", "g-bal", 100, 600, [
                    {"position": 500, "key": "balance",
                     "before": 1000, "after": 2500}]))]}, f)
        ap.cmd_publish(store, bp)
        out_path = os.path.join(tmp.name, "diff.json")
        proc = subprocess.run(
            [sys.executable, "-I", str(ROOT / "version_compare.py"),
             "store", store, "--from", "0", "--to", "1", "-o", out_path],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out_path, encoding="utf-8") as f:
            result = json.load(f)
        self.assertEqual(result["versions"]["from"]["version"], 0)
        self.assertEqual(result["versions"]["to"]["version"], 1)
        self.assertGreater(result["change_count"], 0)
        for c in result["changes"]:
            self.assertIn("half_open", c["range"])
            self.assertIn(c["from"]["status"],
                          ("confirmed", "conflict", "insufficient"))

    def test_files_cli_and_error_codes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pa = os.path.join(tmp.name, "a.json")
        pb = os.path.join(tmp.name, "b.json")
        with open(pa, "w") as f:
            json.dump({"history": {"lo": 0, "hi": 10}, "keys": ["k"],
                       "writes": [], "gaps": []}, f)
        with open(pb, "w") as f:
            json.dump({"history": {"lo": 0, "hi": 10}, "keys": ["z"],
                       "writes": [], "gaps": []}, f)
        # 无共同键名册 -> 退出码 2
        proc = subprocess.run(
            [sys.executable, "-I", str(ROOT / "version_compare.py"),
             "files", "--archive-a", pa, "--archive-b", pb],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("compare_error", proc.stderr)
        # 案卷文件不存在 -> 退出码 2（比较无法进行）
        proc = subprocess.run(
            [sys.executable, "-I", str(ROOT / "version_compare.py"),
             "files", "--archive-a", pa, "--archive-b",
             os.path.join(tmp.name, "nope.json")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)

    def test_existing_commands_still_work(self):
        # 回归：发布器与查询器原有入口不受影响
        proc = subprocess.run(
            [sys.executable, "-I", str(ROOT / "forensic_query.py"),
             str(ROOT / "samples" / "case_archive.json")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["query_count"], 9)


if __name__ == "__main__":
    unittest.main()

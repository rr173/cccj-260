# -*- coding: utf-8 -*-
"""archive_publisher 的单元测试。运行：python3 -I -m unittest -v"""

import contextlib
import fcntl
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import archive_publisher as ap  # noqa: E402
from forensic_query import Archive  # noqa: E402

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


class PublisherCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = os.path.join(self.tmp.name, "store")
        self.settings_path = os.path.join(self.tmp.name, "settings.json")
        with open(self.settings_path, "w", encoding="utf-8") as f:
            json.dump(make_settings(), f)
        ap.cmd_init(self.store, self.settings_path)

    def write_batch(self, batch, name="batch.json"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(batch, f)
        return path

    def publish(self, batch, name="batch.json"):
        return ap.cmd_publish(self.store, self.write_batch(batch, name))

    def load_release(self, version):
        rel = os.path.join(self.store, "releases", "v%d" % version)
        with open(os.path.join(rel, "archive.json"), encoding="utf-8") as f:
            arch = json.load(f)
        with open(os.path.join(rel, "provenance.json"), encoding="utf-8") as f:
            prov = json.load(f)
        return arch, prov

    def current_version(self):
        with open(os.path.join(self.store, "CURRENT"), encoding="utf-8") as f:
            return int(f.read().strip())

    def base_batch1(self):
        """A/B 互补合成 balance@500；C 提供 owner@700。"""
        return {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
            op_add(vol("B", "g-bal", 400, 900, [
                {"position": 500, "key": "balance", "after": 2500}])),
            op_add(vol("C", "g-own", 100, 900, [
                {"position": 700, "key": "owner", "after": "alice"}])),
        ]}


class TestInit(PublisherCase):
    def test_init_creates_v0_all_uncovered(self):
        self.assertEqual(self.current_version(), 0)
        arch, prov = self.load_release(0)
        # 两组各一条全区间无覆盖缺段；无精确写
        self.assertEqual(arch["writes"], [])
        self.assertEqual(
            {(g["range"]["a"], g["range"]["b"], tuple(g["keys"]))
             for g in arch["gaps"]},
            {(1, 1000, ("balance",)), (1, 1000, ("owner",))},
        )
        for g in arch["gaps"]:
            self.assertEqual(prov["materials"][g["id"]]["reason"],
                             "no_coverage")
        # 独立材料原样保留
        self.assertEqual(arch["snapshot"]["values"]["balance"], 4200)
        self.assertEqual(len(arch["checks"]), 2)
        self.assertEqual(prov["materials"]["terminal-snapshot"]["origin"],
                         "settings")
        self.assertEqual(prov["materials"]["chk-bal"]["origin"], "settings")
        # 现有工具直接可查
        a = Archive(arch)
        self.assertEqual(a.evaluate(500, "balance")["status"], "insufficient")
        r = a.evaluate(999, "balance")
        self.assertEqual((r["status"], r["value"]), ("confirmed", 4200))
        r = a.evaluate(300, "owner")
        self.assertEqual((r["status"], r["value"]), ("confirmed", "alice"))
        self.assertEqual(r["applicability"],
                         {"start": 300, "end": 301, "half_open": True})

    def test_init_rejects_nonempty_dir_and_bad_settings(self):
        with self.assertRaises(ap.StoreError):
            ap.cmd_init(self.store, self.settings_path)
        bad = make_settings()
        bad["groups"] = {"g1": ["balance"], "g2": ["balance", "owner"]}
        p = os.path.join(self.tmp.name, "bad.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(bad, f)
        with self.assertRaises(ap.StructuralError):
            ap.cmd_init(os.path.join(self.tmp.name, "s2"), p)
        # 组未覆盖名册
        bad2 = make_settings()
        bad2["groups"] = {"g1": ["balance"]}
        with open(p, "w", encoding="utf-8") as f:
            json.dump(bad2, f)
        with self.assertRaises(ap.StructuralError):
            ap.cmd_init(os.path.join(self.tmp.name, "s3"), p)
        # 核对单 id 撞保留前缀
        bad3 = make_settings()
        bad3["checks"] = [{"id": "log:w:1:balance", "position": 1,
                           "key": "balance", "value": 1}]
        with open(p, "w", encoding="utf-8") as f:
            json.dump(bad3, f)
        with self.assertRaises(ap.StructuralError):
            ap.cmd_init(os.path.join(self.tmp.name, "s4"), p)


class TestMergeAndProvenance(PublisherCase):
    def test_complementary_merge_and_provenance(self):
        out = self.publish(self.base_batch1())
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["merged_groups"], ["g-bal", "g-own"])
        arch, prov = self.load_release(1)

        writes = {w["id"]: w for w in arch["writes"]}
        self.assertEqual(set(writes), {"log:w:500:balance", "log:w:700:owner"})
        self.assertEqual(writes["log:w:500:balance"],
                         {"id": "log:w:500:balance", "position": 500,
                          "key": "balance", "before": 1000, "after": 2500})
        # 来源清单：A 提供双侧，B 只提供 after
        src = prov["materials"]["log:w:500:balance"]["sources"]
        self.assertEqual(
            [{k: v for k, v in s.items() if k != "range"} for s in src],
            [{"volume_id": "A", "before": 1000, "after": 2500},
             {"volume_id": "B", "after": 2500}],
        )
        self.assertEqual({v["volume_id"] for v in prov["roster"]},
                         {"A", "B", "C"})
        # 无覆盖缺段可区分
        reasons = {m["reason"] for m in prov["materials"].values()
                   if m["kind"] == "gap"}
        self.assertEqual(reasons, {"no_coverage"})

        a = Archive(arch)
        self.assertEqual(a.evaluate(450, "balance")["value"], 1000)
        self.assertEqual(a.evaluate(600, "balance")["value"], 2500)
        self.assertEqual(a.evaluate(50, "balance")["status"], "insufficient")
        self.assertEqual(a.evaluate(950, "balance")["status"], "insufficient")
        self.assertEqual(a.evaluate(500, "owner")["value"], "alice")
        self.assertEqual(a.evaluate(800, "owner")["value"], "alice")
        self.assertEqual(a.evaluate(50, "owner")["status"], "insufficient")

    def test_explicit_null_and_missing_side(self):
        batch = {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 550, "key": "balance", "before": None}])),
            op_add(vol("B", "g-bal", 400, 900, [
                {"position": 550, "key": "balance", "after": 7}])),
        ]}
        self.publish(batch)
        arch, prov = self.load_release(1)
        w = [w for w in arch["writes"] if w["position"] == 550][0]
        # 明确 null 是提供的值；两侧互补合成
        self.assertEqual(w, {"id": "log:w:550:balance", "position": 550,
                             "key": "balance", "before": None, "after": 7})
        src = prov["materials"]["log:w:550:balance"]["sources"]
        self.assertEqual(
            [{k: v for k, v in s.items() if k != "range"} for s in src],
            [{"volume_id": "A", "before": None},
             {"volume_id": "B", "after": 7}],
        )

    def test_unlisted_side_stays_default(self):
        # 两卷都只给 after：合成写没有 before 一侧
        batch = {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance", "after": 1}])),
            op_add(vol("B", "g-bal", 400, 900, [
                {"position": 500, "key": "balance", "after": 1}])),
        ]}
        self.publish(batch)
        arch, _ = self.load_release(1)
        w = [w for w in arch["writes"] if w["position"] == 500][0]
        self.assertNotIn("before", w)
        self.assertEqual(w["after"], 1)

    def test_dispute_listed_vs_unlisted(self):
        batch = {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance",
                 "before": 1000, "after": 2500}])),
            op_add(vol("B", "g-bal", 400, 900, [])),  # 覆盖 500 但未列写
            op_add(vol("C", "g-own", 100, 900, [
                {"position": 700, "key": "owner", "after": "alice"}])),
        ]}
        self.publish(batch)
        arch, prov = self.load_release(1)
        # 争议写不交给查询端（balance@500 消失，owner@700 不受影响）
        self.assertEqual({w["id"] for w in arch["writes"]},
                         {"log:w:700:owner"})
        gap = [g for g in arch["gaps"] if g["id"] == "log:d:500:balance"][0]
        self.assertEqual(gap["range"], {"a": 500, "b": 501})
        self.assertEqual(gap["keys"], ["balance"])
        m = prov["materials"]["log:d:500:balance"]
        self.assertEqual(m["reason"], "dispute")
        self.assertEqual(m["cause"], "listed_and_unlisted")
        claims = {c["volume_id"]: c for c in m["claims"]}
        self.assertEqual(claims["A"]["claim"], "write")
        self.assertEqual(claims["A"]["after"], 2500)
        self.assertEqual(claims["B"]["claim"], "unlisted")
        # 争议写的部分值不外泄：右侧查不到 2500
        a = Archive(arch)
        self.assertEqual(a.evaluate(600, "balance")["status"], "insufficient")
        # 左侧连续性仍在（核对单 chk-bal@100）
        self.assertEqual(a.evaluate(450, "balance")["value"], 1000)
        # 只隔离该键该边界：owner 不受牵连
        self.assertEqual(a.evaluate(500, "owner")["value"], "alice")

    def test_dispute_conflicting_side_values(self):
        batch = {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance", "after": 2500}])),
            op_add(vol("B", "g-bal", 400, 900, [
                {"position": 500, "key": "balance", "after": 2600}])),
        ]}
        self.publish(batch)
        arch, prov = self.load_release(1)
        self.assertEqual(arch["writes"], [])
        m = prov["materials"]["log:d:500:balance"]
        self.assertEqual(m["cause"], "conflicting_side_values")
        afters = {c["volume_id"]: c.get("after") for c in m["claims"]}
        self.assertEqual(afters, {"A": 2500, "B": 2600})

    def test_snapshot_checks_other_keys_survive_dispute(self):
        batch = {"base": 0, "changes": [
            op_add(vol("A", "g-bal", 100, 600, [
                {"position": 500, "key": "balance", "after": 2500}])),
            op_add(vol("B", "g-bal", 400, 900, [])),
            op_add(vol("C", "g-own", 100, 900, [
                {"position": 700, "key": "owner", "after": "alice"}])),
        ]}
        self.publish(batch)
        arch, _ = self.load_release(1)
        self.assertIn("snapshot", arch)
        self.assertEqual(len(arch["checks"]), 2)
        a = Archive(arch)
        self.assertEqual(a.evaluate(999, "balance")["value"], 4200)
        self.assertEqual(a.evaluate(800, "owner")["value"], "alice")


class TestBatchLifecycle(PublisherCase):
    def test_replace_rejudges_old_and_new_ranges(self):
        self.publish(self.base_batch1())
        # B 换卷：范围 [400,900) 缩为 [400,800)；旧范围 [800,900) 重新判定
        b2 = vol("B", "g-bal", 400, 800,
                 [{"position": 500, "key": "balance", "after": 2500}])
        out = self.publish({"base": 1, "changes": [op_replace("B", b2)]},
                           "b2.json")
        self.assertEqual(out["changes"]["replaced"], ["B"])
        arch, _ = self.load_release(2)
        gap_ids = {g["id"] for g in arch["gaps"]}
        self.assertIn("log:u:g-bal:800:1000", gap_ids)   # 旧范围后段变无覆盖
        self.assertNotIn("log:u:g-bal:900:1000", gap_ids)
        self.assertIn("log:w:500:balance", {w["id"] for w in arch["writes"]})

    def test_withdraw_volume(self):
        self.publish(self.base_batch1())
        self.publish({"base": 1, "changes": [op_withdraw("B")]}, "b2.json")
        arch, prov = self.load_release(2)
        w = [w for w in arch["writes"] if w["id"] == "log:w:500:balance"][0]
        self.assertEqual((w["before"], w["after"]), (1000, 2500))
        src = prov["materials"]["log:w:500:balance"]["sources"]
        self.assertEqual([s["volume_id"] for s in src], ["A"])
        self.assertEqual({v["volume_id"] for v in prov["roster"]}, {"A", "C"})

    def test_stale_base_rejected(self):
        self.publish(self.base_batch1())
        with self.assertRaises(ap.BatchRejected):
            self.publish(self.base_batch1(), "again.json")  # base 仍是 0
        self.assertEqual(self.current_version(), 1)
        self.assertFalse(os.path.exists(
            os.path.join(self.store, "releases", "v2")))

    def test_first_batch_must_be_based_on_v0(self):
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 1, "changes": []})

    def test_duplicate_volume_id_in_batch_rejected(self):
        v = vol("X", "g-bal", 100, 200, [])
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 0, "changes": [op_add(v), op_add(v)]})
        self.publish(self.base_batch1())
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 1, "changes":
                          [op_replace("A", vol("A", "g-bal", 100, 200, [])),
                           op_withdraw("A")]}, "dup.json")

    def test_unknown_or_existing_volume_id_rejected(self):
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 0, "changes": [op_withdraw("nope")]})
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 0, "changes": [
                op_replace("nope", vol("nope", "g-bal", 100, 200, []))]})
        self.publish(self.base_batch1())
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 1, "changes": [
                op_add(vol("A", "g-bal", 100, 200, []))]}, "b2.json")

    def test_replace_id_must_match(self):
        self.publish(self.base_batch1())
        with self.assertRaises(ap.BatchRejected):
            self.publish({"base": 1, "changes": [
                op_replace("A", vol("B", "g-bal", 100, 200, []))]}, "b2.json")

    def test_invalid_volumes_rejected_and_nothing_changes(self):
        bad_volumes = [
            vol("V", "g-bal", 100, 200,
                [{"position": 50, "key": "balance", "after": 1}]),   # 写出范围
            vol("V", "g-bal", 100, 200,
                [{"position": 150, "key": "owner", "after": 1}]),    # 键不属组
            vol("V", "g-nope", 100, 200, []),                        # 未知组
            vol("V", "g-bal", 0, 200, []),                           # a 越界
            vol("V", "g-bal", 100, 1001, []),                        # b 越界
            vol("V", "g-bal", 200, 200, []),                         # 空区间
            vol("V", "g-bal", 100, 200,
                [{"position": 150, "key": "balance"}]),              # 无侧值
            vol("V", "g-bal", 100, 200,
                [{"position": 150, "key": "balance", "after": True}]),  # bool
            vol("V", "g-bal", 100, 200, [
                {"position": 150, "key": "balance", "after": 1},
                {"position": 150, "key": "balance", "before": 0}]),  # 同卷重复
            {"group": "g-bal", "range": {"a": 100, "b": 200}},       # 缺卷号
        ]
        for i, bv in enumerate(bad_volumes):
            with self.assertRaises(ap.BatchRejected, msg="case %d" % i):
                self.publish({"base": 0, "changes": [op_add(bv)]},
                             "bad%d.json" % i)
        self.assertEqual(self.current_version(), 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.store, "releases", "v1")))

    def test_batch_atomic_no_partial_changes(self):
        batch = {"base": 0, "changes": [
            op_add(vol("ok", "g-bal", 100, 200, [])),
            op_add(vol("bad", "g-bal", 100, 200,
                       [{"position": 150, "key": "balance"}])),
        ]}
        with self.assertRaises(ap.BatchRejected):
            self.publish(batch)
        self.assertEqual(self.current_version(), 0)
        _, prov = self.load_release(0)
        self.assertEqual(prov["roster"], [])


class TestVersioning(PublisherCase):
    def test_old_versions_immutable_while_readers_hold_them(self):
        self.publish(self.base_batch1())
        _, prov1_before = self.load_release(1)
        with open(os.path.join(self.store, "releases", "v1",
                               "archive.json"), "rb") as f:
            arch1_bytes = f.read()
        # 读者仍拿着 v1 时，发布 v2
        self.publish({"base": 1, "changes": [op_withdraw("B")]}, "b2.json")
        self.assertEqual(self.current_version(), 2)
        with open(os.path.join(self.store, "releases", "v1",
                               "archive.json"), "rb") as f:
            self.assertEqual(f.read(), arch1_bytes)  # 旧版字节不变
        _, prov1_after = self.load_release(1)
        self.assertEqual(prov1_before, prov1_after)

    def test_crash_leftover_temps_cleaned_and_no_half_version(self):
        self.publish(self.base_batch1())
        # 模拟上次发布中途被终止的残留
        os.makedirs(os.path.join(self.store, "releases", ".tmp-v2-999"))
        for junk in ("volumes/x.tmp-9", "fragments/y.tmp-9", "z.tmp-9"):
            with open(os.path.join(self.store, junk), "w") as f:
                f.write("junk")
        out = self.publish({"base": 1, "changes": [op_withdraw("A")]}, "b2.json")
        self.assertEqual(out["version"], 2)
        for junk in ("volumes/x.tmp-9", "fragments/y.tmp-9", "z.tmp-9",
                     "releases/.tmp-v2-999"):
            self.assertFalse(os.path.exists(os.path.join(self.store, junk)))
        # v1 仍完整可读
        arch, _ = self.load_release(1)
        Archive(arch)

    def test_single_publisher_lock(self):
        batch_path = self.write_batch(self.base_batch1())
        fd = os.open(os.path.join(self.store, ".lock"),
                     os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                rc = ap.main(["publish", self.store, "--batch", batch_path])
            self.assertEqual(rc, 3)
        finally:
            os.close(fd)
        # 锁释放后可发布
        out = self.publish(self.base_batch1())
        self.assertEqual(out["version"], 1)

    def test_unchanged_group_volumes_not_reread(self):
        self.publish(self.base_batch1())
        # 找到 g-own 组 C 卷的原始文件并移走：若发布器重读未变组原卷会失败
        meta = ap._load_meta(self.store, 1)
        sha_c = meta["roster"]["C"]["sha256"]
        src = os.path.join(self.store, "volumes", sha_c + ".json")
        hidden = src + ".hidden"
        os.rename(src, hidden)
        try:
            a2 = vol("A", "g-bal", 100, 700,
                     [{"position": 500, "key": "balance",
                       "before": 1000, "after": 2500}])
            out = self.publish({"base": 1, "changes": [op_replace("A", a2)]},
                               "b2.json")
            self.assertEqual(out["merged_groups"], ["g-bal"])
            self.assertEqual(out["reused_groups"], ["g-own"])
            arch, _ = self.load_release(2)
            # 未变组的整理结果被重新组合进新案卷
            self.assertIn("log:w:700:owner",
                          {w["id"] for w in arch["writes"]})
        finally:
            os.rename(hidden, src)


class TestReaderFlow(PublisherCase):
    def test_cli_and_existing_query_tool_end_to_end(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ap.main(["publish", self.store, "--batch",
                                      self.write_batch(self.base_batch1())]), 0)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(ap.main(["current", self.store]), 0)
        cur = json.loads(buf.getvalue())
        self.assertEqual(cur["version"], 1)
        queries = os.path.join(self.tmp.name, "q.json")
        with open(queries, "w", encoding="utf-8") as f:
            json.dump({"queries": [{"position": 450, "key": "balance"},
                                   {"position": 600, "key": "balance"},
                                   {"position": 50, "key": "owner"}]}, f)
        proc = subprocess.run(
            [sys.executable, "-I", str(ROOT / "forensic_query.py"),
             cur["archive"], "-q", queries],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(proc.stdout)
        rm = {(r["position"], r["key"]): r for r in out["results"]}
        self.assertEqual(rm[(450, "balance")]["value"], 1000)
        self.assertEqual(rm[(600, "balance")]["value"], 2500)
        self.assertEqual(rm[(50, "owner")]["status"], "insufficient")
        # 来源清单与案卷同版
        with open(cur["provenance"], encoding="utf-8") as f:
            prov = json.load(f)
        self.assertEqual(prov["version"], 1)

    def test_cli_exit_codes(self):
        # 过期基版 -> 2
        self.publish(self.base_batch1())
        with contextlib.redirect_stderr(io.StringIO()):
            rc = ap.main(["publish", self.store, "--batch",
                          self.write_batch(self.base_batch1(), "b.json")])
        self.assertEqual(rc, 2)
        # 批次文件不可读 -> 1
        with contextlib.redirect_stderr(io.StringIO()):
            rc = ap.main(["publish", self.store, "--batch",
                          os.path.join(self.tmp.name, "missing.json")])
        self.assertEqual(rc, 1)
        # 未初始化目录 -> 1
        with contextlib.redirect_stderr(io.StringIO()):
            rc = ap.main(["current", os.path.join(self.tmp.name, "nope")])
        self.assertEqual(rc, 1)


class TestSparse(PublisherCase):
    def test_huge_history_no_expansion(self):
        huge = 10 ** 12
        settings = {
            "history": {"lo": 0, "hi": huge},
            "keys": ["k1", "k2"],
            "groups": {"g1": ["k1"], "g2": ["k2"]},
            "snapshot": {"values": {"k1": 1, "k2": "s"}},
        }
        sp = os.path.join(self.tmp.name, "big-settings.json")
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(settings, f)
        store = os.path.join(self.tmp.name, "big-store")
        ap.cmd_init(store, sp)
        batch = {"base": 0, "changes": [
            op_add(vol("V1", "g1", 2, huge // 2, [
                {"position": huge // 4, "key": "k1",
                 "before": 0, "after": 1}])),
            op_add(vol("V2", "g1", huge // 5, huge, [
                {"position": huge // 4, "key": "k1", "after": 1}])),
        ]}
        bp = self.write_batch(batch, "big-batch.json")
        ap.cmd_publish(store, bp)
        rel = os.path.join(store, "releases", "v1")
        with open(os.path.join(rel, "archive.json"), encoding="utf-8") as f:
            arch = json.load(f)
        # 材料条数是常数级，与位置跨度无关
        self.assertLessEqual(len(arch["gaps"]) + len(arch["writes"]), 12)
        a = Archive(arch)
        r = a.evaluate(huge // 4 - 1, "k1")
        self.assertEqual((r["status"], r["value"]), ("confirmed", 0))
        r = a.evaluate(huge - 2, "k2")
        self.assertEqual(r["status"], "insufficient")  # 无覆盖孤立点
        r = a.evaluate(huge - 1, "k2")
        self.assertEqual((r["status"], r["value"]), ("confirmed", "s"))


if __name__ == "__main__":
    unittest.main()

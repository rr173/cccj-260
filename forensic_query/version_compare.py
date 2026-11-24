#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
版本比较入口（只读，不修改发布库、案卷或任何输入材料）。

给定发布库中的两个已发布版本（或两卷案卷文件），在两版**共同的历史区间
与键名册**内，逐键比较每个历史位置上的取证结论与依据，输出发生变化的
历史位置范围。全部计算基于组件区间合并与二分，不随历史位置数量展开，
可用于 10¹² 级跨度。

结论口径与 forensic_query.Archive.evaluate 完全一致：
  * confirmed（含明确 null）/ conflict / insufficient 互为不同状态；
  * 值相同但所依赖实据（材料 id、来源分卷）或可连续范围（组件/适用区间）
    不同，也算变化；
  * insufficient 进一步说明成因：
      no_coverage      对应位置无覆盖（缺段孤立点，无分卷覆盖该边界）；
      dispute          存在材料分歧（争议写被隔离，不交给查询端）；
      lack_of_evidence 缺少可用于确认该值的实据（可达连续区间内无证据）。
输出合并相邻且两版结论及依据均相同的范围，不输出没有变化的部分。

用法
----
  python3 -I version_compare.py store 发布库目录 --from 1 --to 3 [-o 结果.json]
  python3 -I version_compare.py files \\
      --archive-a 案卷A.json [--provenance-a 来源A.json] \\
      --archive-b 案卷B.json [--provenance-b 来源B.json] [-o 结果.json]

退出码：0 正常；1 读文件/JSON 解析失败；2 材料结构无效或两版没有
可比较的共同历史区间/键名册。
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# python3 -I（隐含 -P）不会把脚本目录放进 sys.path，这里显式补上
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forensic_query import Archive, StructuralError  # noqa: E402

# evidence不足的三种成因（输出 reason 字段取值）
INS_NO_COVERAGE = "no_coverage"
INS_DISPUTE = "dispute"
INS_LACK = "lack_of_evidence"

REASON_MESSAGES = {
    INS_NO_COVERAGE: "对应位置无覆盖：没有现行分卷覆盖该边界，"
                     "缺段内位置彼此孤立且没有恰好落点的实据",
    INS_DISPUTE: "存在材料分歧：覆盖该边界的分卷主张不一致，"
                 "争议写被隔离、不交给查询端，该位置无实据可用",
    INS_LACK: "缺少可用于确认该值的实据：证据可达的连续区间内"
              "没有任何真实证据，且不能跨阻断边界推值",
}


class CompareError(Exception):
    """比较无法进行（无共同历史区间/键名册、版本不存在等）。"""


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: str, what: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise CompareError("无法读取%s: %s" % (what, exc))


def _canonical(obj: Any) -> str:
    """结论/依据的规范签名：任何字段差异都会体现为不同签名。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _merge_gap_intervals(
    intervals: List[Tuple[int, int, str]]
) -> Tuple[List[int], List[int], List[List[str]]]:
    """把 (a,b,gap_id) 列表合并为互不重叠的区间，每段带上全部缺口 id。"""
    if not intervals:
        return [], [], []
    intervals = sorted(intervals)
    starts: List[int] = []
    ends: List[int] = []
    id_lists: List[List[str]] = []
    ca, cb, cids = intervals[0][0], intervals[0][1], [intervals[0][2]]
    for a, b, gid in intervals[1:]:
        if a <= cb:  # 相邻缺口也合并：其中的位置同样处于孤立态
            cb = max(cb, b)
            if gid not in cids:
                cids.append(gid)
        else:
            starts.append(ca)
            ends.append(cb)
            id_lists.append(cids)
            ca, cb, cids = a, b, [gid]
    starts.append(ca)
    ends.append(cb)
    id_lists.append(cids)
    return starts, ends, id_lists


# --------------------------------------------------------------------------
# 单版视图：案卷 + 来源清单 + 缺口/分歧索引
# --------------------------------------------------------------------------

class VersionView:
    def __init__(self, doc: Any, provenance: Optional[dict], label: str):
        # Archive 构造即完成全部结构校验（与查询端同一内核）
        self.arch = Archive(doc)
        self.doc = doc
        self.prov = provenance if isinstance(provenance, dict) else {}
        self.label = label
        self.prov_materials: Dict[str, Any] = self.prov.get("materials", {})
        if not isinstance(self.prov_materials, dict):
            self.prov_materials = {}
        self._build_gap_index()
        self._build_dispute_boundaries()

    # ----- 来源清单 -----

    def _reason_of(self, gap_id: str) -> Optional[str]:
        m = self.prov_materials.get(gap_id)
        if isinstance(m, dict) and isinstance(m.get("reason"), str):
            return m["reason"]
        # 没有来源清单时，按发布器保留 id 约定兜底识别
        if gap_id.startswith("log:d:"):
            return INS_DISPUTE
        if gap_id.startswith("log:u:"):
            return INS_NO_COVERAGE
        return None

    def _enrich(self, mat: dict) -> dict:
        out = dict(mat)
        prov = self.prov_materials.get(mat.get("material_id"))
        if prov is not None:
            out["provenance"] = prov
        return out

    def _enrich_evidence(self, mats: List[dict]) -> List[dict]:
        ordered = sorted(
            mats,
            key=lambda m: (m.get("position", -1), str(m.get("material_id", ""))),
        )
        return [self._enrich(m) for m in ordered]

    def _gap_basis(self, gap_id: str) -> dict:
        out: Dict[str, Any] = {"material_id": gap_id, "kind": "gap"}
        reason = self._reason_of(gap_id)
        if reason is not None:
            out["reason"] = reason
        prov = self.prov_materials.get(gap_id)
        if prov is not None:
            out["provenance"] = prov
        return out

    # ----- 缺口索引 -----

    def _build_gap_index(self) -> None:
        per_key: Dict[str, List[Tuple[int, int, str]]] = {
            k: [] for k in self.arch.keys
        }
        glob: List[Tuple[int, int, str]] = []
        gaps = self.doc.get("gaps", [])
        if not isinstance(gaps, list):
            gaps = []
        for g in gaps:
            a, b, gid = g["range"]["a"], g["range"]["b"], g["id"]
            entry = (a, b, gid)
            if g.get("keys") is None:
                glob.append(entry)
            else:
                for k in g["keys"]:
                    per_key[k].append(entry)
        self._gap_starts: Dict[str, List[int]] = {}
        self._gap_ends: Dict[str, List[int]] = {}
        self._gap_ids: Dict[str, List[List[str]]] = {}
        for k in self.arch.keys:
            s, e, ids = _merge_gap_intervals(per_key[k] + glob)
            self._gap_starts[k] = s
            self._gap_ends[k] = e
            self._gap_ids[k] = ids

    def gaps_at(self, key: str, pos: int) -> List[str]:
        """返回覆盖位置 pos 的全部缺口 id（按键专属 + 全体键合并）。"""
        starts = self._gap_starts[key]
        i = bisect.bisect_right(starts, pos) - 1
        if i >= 0 and starts[i] <= pos < self._gap_ends[key][i]:
            return list(self._gap_ids[key][i])
        return []

    def _build_dispute_boundaries(self) -> None:
        """边界位置 p -> 该键在 p 上的分歧缺口 id（来源清单 reason=dispute）。"""
        self._disputes: Dict[str, Dict[int, List[str]]] = {
            k: {} for k in self.arch.keys
        }
        gaps = self.doc.get("gaps", [])
        if not isinstance(gaps, list):
            return
        for g in gaps:
            if self._reason_of(g["id"]) != INS_DISPUTE:
                continue
            a, b = g["range"]["a"], g["range"]["b"]
            if b != a + 1:
                continue  # 发布器的分歧缺口恒为单边界 [p,p+1)
            affected = self.arch.keys if g.get("keys") is None else g["keys"]
            for k in affected:
                self._disputes[k].setdefault(a, []).append(g["id"])

    # ----- 结论归一化（与 evaluate 同口径，去掉位置相关字段，补来源/成因）-----

    def conclusion_at(self, key: str, pos: int) -> dict:
        r = self.arch.evaluate(pos, key)
        status = r["status"]
        if status == "confirmed":
            return {
                "status": "confirmed",
                "value": r["value"],
                "component": r["component"],
                "applicability": r["applicability"],
                "evidence": self._enrich_evidence(r["evidence"]),
            }
        if status == "conflict":
            return {
                "status": "conflict",
                "component": r["component"],
                "conflicting_evidence": [
                    {"value": c["value"],
                     "materials": self._enrich_evidence(c["materials"])}
                    for c in r["conflicting_evidence"]
                ],
                "message": r["message"],
            }
        return self._insufficient(key, r["component"], pos)

    def _insufficient(self, key: str, component: dict, pos: int) -> dict:
        ca, cb, kind = component["start"], component["end"], component["kind"]
        basis: List[dict] = []
        if kind == "gap":
            gap_ids = self.gaps_at(key, pos)
            known = {self._reason_of(g) for g in gap_ids}
            reasons = {r for r in known if r is not None}
            basis = [self._gap_basis(g) for g in gap_ids]
            if INS_DISPUTE in reasons:
                reason = INS_DISPUTE
            elif reasons <= {INS_NO_COVERAGE}:
                # 含明确的 no_coverage，或来源清单缺失（reasons 为空）时
                # 缺段组件内的孤立无证据，统一按无覆盖处理
                reason = INS_NO_COVERAGE
            else:
                reason = INS_LACK
        else:
            # 自由组件内无证据：若组件两端的阻断边界来自材料分歧，
            # 则不足源于分歧隔离；否则就是普通的实据缺失。
            dispute_ids: List[str] = []
            if ca > self.arch.lo:  # 边界 ca（边 ca-1 -> ca）
                dispute_ids.extend(self._disputes[key].get(ca, ()))
            if cb <= self.arch.hi and cb > self.arch.lo:  # 边界 cb
                dispute_ids.extend(self._disputes[key].get(cb, ()))
            if dispute_ids:
                reason = INS_DISPUTE
                seen = set()
                basis = []
                for gid in dispute_ids:
                    if gid not in seen:
                        seen.add(gid)
                        basis.append(self._gap_basis(gid))
            else:
                reason = INS_LACK
        return {
            "status": "insufficient",
            "component": component,
            "reason": reason,
            "reason_message": REASON_MESSAGES[reason],
            "basis_materials": basis,
        }

    # ----- 组件 -> 结论恒定的分段（区间表示，不展开位置）-----

    def segments(
        self, key: str, lo: int, hi: int
    ) -> List[Tuple[int, int, dict]]:
        """
        在 [lo,hi) 上产出 (a,b,结论) 分段，保证段内每个位置的结论与依据
        完全相同。分段边界只来自：组件边界、缺口区间边界、实据位置，
        数量随材料条数增长，与历史跨度无关。
        """
        starts, ends, kinds = self.arch._components_for(key)
        out: List[Tuple[int, int, dict]] = []
        i = bisect.bisect_right(ends, lo)
        while i < len(starts) and starts[i] < hi:
            a, b, kind = starts[i], ends[i], kinds[i]
            ca, cb = max(a, lo), min(b, hi)
            if kind == "free":
                # 自由组件内结论处处相同，取代表位置 ca 计算一次
                out.append((ca, cb, self.conclusion_at(key, ca)))
            else:
                out.extend(self._gap_component_segments(key, a, b, ca, cb))
            i += 1
        return out

    def _gap_component_segments(
        self, key: str, a: int, b: int, ca: int, cb: int
    ) -> List[Tuple[int, int, dict]]:
        """
        真实缺段组件为 [a,b)（与 evaluate 输出一致）；[ca,cb) 是它落在
        共同历史窗口内的部分，只在该部分内分段。
        """
        ev_list = self.arch.evidence[key]
        ev_positions = [e[0] for e in ev_list]
        left = bisect.bisect_left(ev_positions, ca)
        right = bisect.bisect_left(ev_positions, cb)
        ev_set = set(ev_positions[left:right])

        # 缺口 id 可能在组件内部切换（相邻缺口合并的情形），其边界也作分段点
        gap_breaks: set = set()
        for s, e in zip(self._gap_starts[key], self._gap_ends[key]):
            if e <= ca or s >= cb:
                continue
            if ca < s < cb:
                gap_breaks.add(s)
            if ca < e < cb:
                gap_breaks.add(e)

        breaks = sorted(ev_set | gap_breaks)
        component = {"start": a, "end": b, "kind": "gap"}
        out: List[Tuple[int, int, dict]] = []
        cursor = ca
        for p in breaks:
            if p > cursor:
                out.append((cursor, p,
                            self._insufficient(key, component, cursor)))
            if p in ev_set:
                # 孤立点上的点实据：confirmed 或同点冲突
                out.append((p, p + 1, self.conclusion_at(key, p)))
                cursor = p + 1
            else:
                cursor = p
        if cursor < cb:
            out.append((cursor, cb,
                        self._insufficient(key, component, cursor)))
        return out


# --------------------------------------------------------------------------
# 两版对齐与差异合并
# --------------------------------------------------------------------------

def _pair_segments(
    segs_a: List[Tuple[int, int, dict]],
    segs_b: List[Tuple[int, int, dict]],
    lo: int,
    hi: int,
) -> List[Tuple[int, int, dict, dict]]:
    """按分段边界并集对齐两版；两侧在每个公共小段内结论都恒定。"""
    out: List[Tuple[int, int, dict, dict]] = []
    ia = ib = 0
    pos = lo
    while pos < hi:
        end = min(segs_a[ia][1], segs_b[ib][1])
        out.append((pos, end, segs_a[ia][2], segs_b[ib][2]))
        pos = end
        if segs_a[ia][1] == end:
            ia += 1
        if segs_b[ib][1] == end:
            ib += 1
    return out


def _collect_changes(
    key: str,
    paired: List[Tuple[int, int, dict, dict]],
) -> List[dict]:
    """筛出结论/依据不同的小段，并合并相邻且两侧签名都相同的变化段。"""
    changes: List[dict] = []
    for a, b, conc_a, conc_b in paired:
        sig_a, sig_b = _canonical(conc_a), _canonical(conc_b)
        if sig_a == sig_b:
            continue
        if changes:
            last = changes[-1]
            if (
                last["key"] == key
                and last["range"]["end"] == a
                and last["_sig_a"] == sig_a
                and last["_sig_b"] == sig_b
            ):
                last["range"]["end"] = b
                continue
        changes.append({
            "key": key,
            "range": {"start": a, "end": b, "half_open": True},
            "from": conc_a,
            "to": conc_b,
            "_sig_a": sig_a,
            "_sig_b": sig_b,
        })
    for c in changes:
        del c["_sig_a"]
        del c["_sig_b"]
    return changes


def compare_views(view_a: VersionView, view_b: VersionView) -> dict:
    arch_a, arch_b = view_a.arch, view_b.arch
    lo = max(arch_a.lo, arch_b.lo)
    hi = min(arch_a.hi, arch_b.hi)
    if lo >= hi:
        raise CompareError(
            "两版没有共同的历史位置区间：[%d,%d) 与 [%d,%d)"
            % (arch_a.lo, arch_a.hi, arch_b.lo, arch_b.hi)
        )
    keys_a = set(arch_a.keys)
    keys_b = set(arch_b.keys)
    common_keys = [k for k in arch_a.keys if k in keys_b]
    if not common_keys:
        raise CompareError("两版键名册没有交集，无法比较")

    changes: List[dict] = []
    for key in common_keys:
        segs_a = view_a.segments(key, lo, hi)
        segs_b = view_b.segments(key, lo, hi)
        paired = _pair_segments(segs_a, segs_b, lo, hi)
        changes.extend(_collect_changes(key, paired))

    excluded = {
        "positions": {
            "from_only": _outer_ranges(arch_a.lo, arch_a.hi, lo, hi),
            "to_only": _outer_ranges(arch_b.lo, arch_b.hi, lo, hi),
        },
        "keys": {
            "from_only": [k for k in arch_a.keys if k not in keys_b],
            "to_only": [k for k in arch_b.keys if k not in keys_a],
        },
    }
    return {
        "scope": {
            "history": {"lo": lo, "hi": hi},
            "keys": common_keys,
            "excluded": excluded,
        },
        "change_count": len(changes),
        "changes": changes,
    }


def _outer_ranges(lo: int, hi: int, common_lo: int, common_hi: int) -> List[list]:
    out = []
    if lo < common_lo:
        out.append([lo, common_lo])
    if common_hi < hi:
        out.append([common_hi, hi])
    return out


# --------------------------------------------------------------------------
# 版本装载（发布库 / 显式文件）
# --------------------------------------------------------------------------

def _version_info(
    label: str,
    archive_path: str,
    provenance_path: Optional[str],
    store: Optional[str] = None,
    version: Optional[int] = None,
) -> Tuple[VersionView, dict]:
    doc = _read_json(archive_path, "案卷 %s" % archive_path)
    prov = None
    prov_sha = None
    if provenance_path is not None:
        prov = _read_json(provenance_path, "来源清单 %s" % provenance_path)
        prov_sha = _sha256_file(provenance_path)
    try:
        view = VersionView(doc, prov, label)
    except StructuralError as exc:
        raise CompareError("案卷 %s 结构无效: %s" % (archive_path, exc))
    pub_version = version
    if pub_version is None and isinstance(doc, dict):
        pub = doc.get("publication")
        if isinstance(pub, dict) and isinstance(pub.get("version"), int):
            pub_version = pub["version"]
    if pub_version is None and isinstance(prov, dict):
        pub_version = prov.get("version")
    info = {
        "label": label,
        "version": pub_version,
        "store": os.path.abspath(store) if store else None,
        "archive": os.path.abspath(archive_path),
        "archive_sha256": _sha256_file(archive_path),
        "provenance": os.path.abspath(provenance_path) if provenance_path else None,
        "provenance_sha256": prov_sha,
        "history": {"lo": view.arch.lo, "hi": view.arch.hi},
        "keys": list(view.arch.keys),
    }
    return view, info


def cmd_compare_store(store: str, va: int, vb: int) -> dict:
    if not os.path.isdir(store):
        raise CompareError("发布库不存在或不是目录: %s" % store)
    loaded = []
    for label, ver in (("from", va), ("to", vb)):
        rel = os.path.join(store, "releases", "v%d" % ver)
        archive_path = os.path.join(rel, "archive.json")
        provenance_path = os.path.join(rel, "provenance.json")
        if not os.path.isfile(archive_path):
            raise CompareError("版本 v%d 的案卷不存在: %s" % (ver, archive_path))
        if not os.path.isfile(provenance_path):
            raise CompareError(
                "版本 v%d 的来源清单不存在: %s" % (ver, provenance_path)
            )
        loaded.append((label, ver, archive_path, provenance_path))
    views = []
    infos = []
    for label, ver, ap, pp in loaded:
        view, info = _version_info(label, ap, pp, store=store, version=ver)
        views.append(view)
        infos.append(info)
    result = compare_views(views[0], views[1])
    return {"versions": {"from": infos[0], "to": infos[1]}, **result}


def cmd_compare_files(
    archive_a: str,
    archive_b: str,
    provenance_a: Optional[str],
    provenance_b: Optional[str],
) -> dict:
    view_a, info_a = _version_info("from", archive_a, provenance_a)
    view_b, info_b = _version_info("to", archive_b, provenance_b)
    result = compare_views(view_a, view_b)
    return {"versions": {"from": info_a, "to": info_b}, **result}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="版本比较：在两版共同历史区间与键名册内，输出取证结论"
                    "及依据发生变化的历史位置范围。只读，不修改任何材料。"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_store = sub.add_parser(
        "store", help="比较发布库中的两个已发布版本")
    p_store.add_argument("store", help="发布库目录")
    p_store.add_argument("--from", dest="from_version", required=True,
                         type=int, help="基准版本号（旧版）")
    p_store.add_argument("--to", dest="to_version", required=True,
                         type=int, help="对照版本号（新版）")
    p_store.add_argument("-o", "--output", help="结果输出文件，省略则写到标准输出")

    p_files = sub.add_parser(
        "files", help="直接比较两卷案卷文件（可分别附来源清单）")
    p_files.add_argument("--archive-a", required=True, help="基准版案卷 JSON")
    p_files.add_argument("--archive-b", required=True, help="对照版案卷 JSON")
    p_files.add_argument("--provenance-a", help="基准版来源清单 provenance.json")
    p_files.add_argument("--provenance-b", help="对照版来源清单 provenance.json")
    p_files.add_argument("-o", "--output", help="结果输出文件，省略则写到标准输出")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "store":
            out = cmd_compare_store(
                args.store, args.from_version, args.to_version)
        else:
            out = cmd_compare_files(
                args.archive_a, args.archive_b,
                args.provenance_a, args.provenance_b)
    except CompareError as exc:
        print(json.dumps({"compare_error": str(exc)},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as exc:
            print(json.dumps({"compare_error": "无法写出结果: %s" % exc},
                             ensure_ascii=False, indent=2), file=sys.stderr)
            return 1
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
案卷发布器（本地发布入口，只写发布库，不改写任何已发布版本）。

各保管组陆续交来完整日志分卷（区段可重叠，可整卷替换或撤回）。本工具把
一批分卷变动合入当前版本，产出一版可直接交给 forensic_query.py 查询的
案卷，并附来源清单：每条采信精确写可追到提供侧值的分卷，每处材料分歧
可追到各卷“列写 / 未列写”的主张。

模型
----
* 案卷设定（init 时固定，之后只读）：历史区间、键名册、互不重叠且覆盖
  名册的保管组；可另带现有格式的终态快照与人工核对单，作为独立材料
  原样保留进每一版案卷。
* 分卷：唯一卷号、所属组、受覆盖的变更边界半开区间 [a,b)（覆盖边界
  a..b-1，要求 lo < a < b <= hi，即案卷内部边界）、其中的精确写清单。
  范围内清单未列出的写即“没发生”；范围外不作证。同卷同边界同键至多
  一条写；before/after 至少给一侧，明确 null 是值、不是未提供。
* 批次：声明基版 base；按卷号 add / replace / withdraw；首批基于 v0
  （空分卷名册）。过期基版、无效材料、同批重复操作同一卷号 -> 整批
  拒绝，不接受部分变动。换卷前后的范围都按现行材料重新判定（该组
  整体重新归并，天然满足）。

合成规则（逐边界逐键，只看覆盖它的现行分卷）
  * 无覆盖                     -> 缺段（no_coverage）；
  * 有覆盖且都未列写            -> 边界保持连续，不产生材料；
  * 有卷列写且有卷在其覆盖内未列写，或各卷同侧值相矛盾
                              -> 只隔离该键该边界：缺段（dispute），
                                 争议写及其部分值不交给查询端；
  * 否则合成一条精确写：不同卷可提供互补前后侧值，都未提供的一侧缺省。
  独立快照、核对单与其他键不因某处分歧作废。

版本与一致性
------------
* 单发布者：.lock 排他；批次先整体校验再落盘，任何一步失败都不改版本。
* releases/v<N>/ 一旦发布不再改动；CURRENT 指针原子切换（tmp+rename）。
  旧版读者不会读到混版；无效批次或发布进程中途被终止不会暴露半版
  （残留的 .tmp-* 在下一次发布时清理，且从不被 CURRENT 引用）。
* 增量：按组归并。未变组直接复用 fragments/ 里已有的整理结果，不重新
  读取或归并其原始分卷；发布时只重新组合各组整理结果。
* 稀疏：区间扫描 + 二分，不随历史位置跨度展开，也不为覆盖变化遍历组内
  全键（生成案卷格式本身要求的键清单除外）。

退出码：0 正常；1 读写/解析失败；2 批次或材料无效（过期基版、无效
分卷、重复操作、未知卷号等）；3 已有发布进程在进行。
"""

from __future__ import annotations

import argparse
import bisect
import fcntl
import hashlib
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

# python3 -I（隐含 -P）不会把脚本目录放进 sys.path，这里显式补上，
# 以便导入同目录的 forensic_query（本工具的查询内核）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forensic_query import Archive, StructuralError, valid_value, value_key

# 生成材料 id 的保留前缀；设定自带的核对单 id 不得使用，以免撞号
RESERVED_ID_PREFIX = "log:"
SNAPSHOT_MATERIAL_ID = "terminal-snapshot"

CURRENT_FILE = "CURRENT"
LOCK_FILE = ".lock"
SETTINGS_FILE = "settings.json"


class BatchRejected(Exception):
    """批次被拒绝（过期基版、无效材料、同批重复操作、未知卷号等）。"""


class StoreError(Exception):
    """发布库状态损坏或读写失败。"""


class PublisherBusy(Exception):
    """已有发布进程持有锁。"""


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_file_atomic(path: str, data: bytes) -> None:
    """tmp 文件 + fsync + rename：读者要么看到旧版要么看到新版。"""
    tmp = "%s.tmp-%d" % (path, os.getpid())
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)
    _fsync_dir(os.path.dirname(path) or ".")


def _read_json(path: str, what: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise StoreError("无法读取%s: %s" % (what, exc))


def _pretty(obj: Any) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# 案卷设定与分卷校验
# --------------------------------------------------------------------------

def validate_settings(doc: Any) -> dict:
    """校验固定案卷设定，返回归一化后的内部表示。"""
    if not isinstance(doc, dict):
        raise StructuralError("案卷设定必须是 JSON 对象")
    # 复用现有 Archive 的结构校验：history/keys/snapshot/checks
    probe: Dict[str, Any] = {
        "history": doc.get("history"),
        "keys": doc.get("keys"),
        "writes": [],
        "gaps": [],
    }
    if "snapshot" in doc:
        probe["snapshot"] = doc.get("snapshot")
    if "checks" in doc:
        probe["checks"] = doc.get("checks")
    arch = Archive(probe)

    groups = doc.get("groups")
    if not isinstance(groups, dict) or not groups:
        raise StructuralError("groups 必须为非空对象：组名 -> 键名册数组")
    seen: Dict[str, str] = {}
    norm_groups: Dict[str, List[str]] = {}
    for g, klist in groups.items():
        if not isinstance(g, str) or not g:
            raise StructuralError("保管组名必须为非空字符串")
        if (
            not isinstance(klist, list)
            or not klist
            or any(not isinstance(k, str) for k in klist)
        ):
            raise StructuralError("保管组 %r 的键名册必须为非空字符串数组" % g)
        if len(set(klist)) != len(klist):
            raise StructuralError("保管组 %r 的键名册存在重复" % g)
        for k in klist:
            if k not in arch.key_set:
                raise StructuralError("保管组 %r 引用了未登记的键 %r" % (g, k))
            if k in seen:
                raise StructuralError(
                    "键 %r 同时属于组 %r 与组 %r；保管组必须互不重叠"
                    % (k, seen[k], g)
                )
            seen[k] = g
        norm_groups[g] = list(klist)
    missing = [k for k in arch.keys if k not in seen]
    if missing:
        raise StructuralError("保管组未覆盖名册键: %r" % (missing,))

    checks = doc.get("checks") or []
    for c in checks:
        cid = c.get("id")
        if isinstance(cid, str) and (
            cid.startswith(RESERVED_ID_PREFIX) or cid == SNAPSHOT_MATERIAL_ID
        ):
            raise StructuralError(
                "核对单 id %r 与发布器保留 id 冲突（保留前缀 %r）"
                % (cid, RESERVED_ID_PREFIX)
            )

    settings: Dict[str, Any] = {
        "lo": arch.lo,
        "hi": arch.hi,
        "keys": list(arch.keys),
        "groups": norm_groups,
    }
    if "snapshot" in doc:
        settings["snapshot"] = doc["snapshot"]
    if checks:
        settings["checks"] = checks
    return settings


def validate_volume(doc: Any, settings: dict, what: str) -> dict:
    """校验一份分卷，返回归一化分卷（writes 按 (position, key) 排序）。"""
    if not isinstance(doc, dict):
        raise BatchRejected("%s 必须为对象" % what)
    vid = doc.get("volume_id")
    if not isinstance(vid, str) or not vid:
        raise BatchRejected("%s 必须带非空字符串 volume_id" % what)
    group = doc.get("group")
    if not isinstance(group, str) or group not in settings["groups"]:
        raise BatchRejected("%s 引用了未登记的保管组 %r" % (what, group))
    rng = doc.get("range")
    if (
        not isinstance(rng, dict)
        or not _is_int(rng.get("a"))
        or not _is_int(rng.get("b"))
    ):
        raise BatchRejected("%s.range 必须为包含整数 a/b 的对象" % what)
    a, b = rng["a"], rng["b"]
    lo, hi = settings["lo"], settings["hi"]
    if not (lo < a < b <= hi):
        raise BatchRejected(
            "%s 覆盖区间 [%d,%d) 无效：须满足 %d < a < b <= %d"
            "（只覆盖案卷内部边界）" % (what, a, b, lo, hi)
        )
    writes = doc.get("writes", [])
    if not isinstance(writes, list):
        raise BatchRejected("%s.writes 必须为数组" % what)
    gkeys = set(settings["groups"][group])
    seen = set()
    out_writes = []
    for i, w in enumerate(writes):
        ww = "%s.writes[%d]" % (what, i)
        if not isinstance(w, dict):
            raise BatchRejected("%s 必须为对象" % ww)
        pos = w.get("position")
        if not _is_int(pos) or not (a <= pos < b):
            raise BatchRejected(
                "%s.position 必须落在卷覆盖区间 [%d,%d) 内" % (ww, a, b)
            )
        key = w.get("key")
        if not isinstance(key, str) or key not in gkeys:
            raise BatchRejected(
                "%s 的键 %r 不属于卷声明的保管组 %r" % (ww, key, group)
            )
        if (pos, key) in seen:
            raise BatchRejected(
                "%s 与卷内另一写重复：同卷同边界同键至多一条写" % ww
            )
        seen.add((pos, key))
        if "before" not in w and "after" not in w:
            raise BatchRejected("%s 至少要给出 before 或 after 之一" % ww)
        entry = {"position": pos, "key": key}
        for side in ("before", "after"):
            if side in w:
                if not valid_value(w[side]):
                    raise BatchRejected(
                        "%s 的 %s 值类型无效（整数、字符串或 null）" % (ww, side)
                    )
                entry[side] = w[side]
        out_writes.append(entry)
    out_writes.sort(key=lambda w: (w["position"], w["key"]))
    return {
        "volume_id": vid,
        "group": group,
        "range": {"a": a, "b": b},
        "writes": out_writes,
    }


# --------------------------------------------------------------------------
# 批次应用
# --------------------------------------------------------------------------

def apply_batch(
    roster: Dict[str, dict], changes: Any, settings: dict
) -> Tuple[Dict[str, dict], Dict[str, Tuple[dict, str, bytes]], dict]:
    """
    整体校验并应用一批变动（不落盘）。返回：
      new_roster   卷号 -> {"group","range","sha256"}
      new_volumes  卷号 -> (归一化分卷, sha256, 规范字节)（新增/替换的卷）
      summary      {"added","replaced","withdrawn"}
    任何一处无效都抛 BatchRejected，调用方保证不产生部分变动。
    """
    if not isinstance(changes, list):
        raise BatchRejected("批次必须包含 changes 数组")
    new_roster = dict(roster)
    new_volumes: Dict[str, Tuple[dict, str, bytes]] = {}
    summary = {"added": [], "replaced": [], "withdrawn": []}
    touched = set()
    for i, op in enumerate(changes):
        what = "changes[%d]" % i
        if not isinstance(op, dict):
            raise BatchRejected("%s 必须为对象" % what)
        kind = op.get("op")
        if kind == "add":
            vol = validate_volume(op.get("volume"), settings, "%s.volume" % what)
            vid = vol["volume_id"]
            if vid in touched:
                raise BatchRejected("同一批重复操作同一卷号 %r" % vid)
            touched.add(vid)
            if vid in new_roster:
                raise BatchRejected("卷号 %r 已存在于现行名册，不能 add" % vid)
            data = _canonical(vol)
            sha = _sha256(data)
            new_volumes[vid] = (vol, sha, data)
            new_roster[vid] = {"group": vol["group"], "range": vol["range"],
                               "sha256": sha}
            summary["added"].append(vid)
        elif kind == "replace":
            vid = op.get("volume_id")
            if not isinstance(vid, str) or not vid:
                raise BatchRejected("%s 必须带非空字符串 volume_id" % what)
            if vid in touched:
                raise BatchRejected("同一批重复操作同一卷号 %r" % vid)
            touched.add(vid)
            if vid not in new_roster:
                raise BatchRejected("卷号 %r 不在现行名册，不能 replace" % vid)
            vol = validate_volume(op.get("volume"), settings, "%s.volume" % what)
            if vol["volume_id"] != vid:
                raise BatchRejected(
                    "replace 的新卷 volume_id %r 必须与被替换卷号 %r 一致"
                    % (vol["volume_id"], vid)
                )
            data = _canonical(vol)
            sha = _sha256(data)
            new_volumes[vid] = (vol, sha, data)
            new_roster[vid] = {"group": vol["group"], "range": vol["range"],
                               "sha256": sha}
            summary["replaced"].append(vid)
        elif kind == "withdraw":
            vid = op.get("volume_id")
            if not isinstance(vid, str) or not vid:
                raise BatchRejected("%s 必须带非空字符串 volume_id" % what)
            if vid in touched:
                raise BatchRejected("同一批重复操作同一卷号 %r" % vid)
            touched.add(vid)
            if vid not in new_roster:
                raise BatchRejected("卷号 %r 不在现行名册，不能 withdraw" % vid)
            del new_roster[vid]
            summary["withdrawn"].append(vid)
        else:
            raise BatchRejected("%s.op 必须为 add/replace/withdraw" % what)
    return new_roster, new_volumes, summary


# --------------------------------------------------------------------------
# 按组归并
# --------------------------------------------------------------------------

def merge_group(
    group: str, keys: List[str], volumes: List[dict], lo: int, hi: int
) -> dict:
    """
    把一组现行分卷归并为整理结果：
      writes     合成精确写（含 sources：各卷提供的侧值）
      uncovered  无覆盖边界区间列表
      disputes   分歧点（含各卷列写/未列写的主张）
    只按边界区间扫描，不逐位置展开，也不遍历组内全键。
    """
    frag: Dict[str, Any] = {
        "group": group,
        "keys": list(keys),
        "writes": [],
        "uncovered": [],
        "disputes": [],
    }
    if lo + 1 >= hi:
        return frag  # 没有内部边界
    if not volumes:
        frag["uncovered"].append({"a": lo + 1, "b": hi})
        return frag

    points = {lo + 1, hi}
    for v in volumes:
        points.add(v["range"]["a"])
        points.add(v["range"]["b"])
    pts = sorted(points)

    # 每条写归属的基本区间下标
    per_interval: Dict[int, List[Tuple[int, dict]]] = {}
    for vi, v in enumerate(volumes):
        for w in v["writes"]:
            idx = bisect.bisect_right(pts, w["position"]) - 1
            per_interval.setdefault(idx, []).append((vi, w))

    adds: Dict[int, List[int]] = {}
    rems: Dict[int, List[int]] = {}
    for vi, v in enumerate(volumes):
        adds.setdefault(v["range"]["a"], []).append(vi)
        rems.setdefault(v["range"]["b"], []).append(vi)
    order = sorted(range(len(volumes)), key=lambda i: volumes[i]["volume_id"])

    active = set()
    for idx in range(len(pts) - 1):
        s, t = pts[idx], pts[idx + 1]
        for vi in rems.get(s, ()):
            active.discard(vi)
        for vi in adds.get(s, ()):
            active.add(vi)
        if not active:
            frag["uncovered"].append({"a": s, "b": t})
            continue
        covering = [vi for vi in order if vi in active]
        by_pk: Dict[Tuple[int, str], Dict[int, dict]] = {}
        for vi, w in per_interval.get(idx, ()):
            by_pk.setdefault((w["position"], w["key"]), {})[vi] = w
        for (p, k) in sorted(by_pk):
            listed = by_pk[(p, k)]
            befores: Dict[Tuple[str, Any], Any] = {}
            afters: Dict[Tuple[str, Any], Any] = {}
            for w in listed.values():
                if "before" in w:
                    befores[value_key(w["before"])] = w["before"]
                if "after" in w:
                    afters[value_key(w["after"])] = w["after"]
            unlisted = [vi for vi in covering if vi not in listed]
            if unlisted or len(befores) > 1 or len(afters) > 1:
                cause = ("listed_and_unlisted" if unlisted
                         else "conflicting_side_values")
                claims = []
                for vi in covering:
                    v = volumes[vi]
                    w = listed.get(vi)
                    if w is None:
                        claims.append({
                            "volume_id": v["volume_id"],
                            "range": v["range"],
                            "claim": "unlisted",
                        })
                    else:
                        claim = {
                            "volume_id": v["volume_id"],
                            "range": v["range"],
                            "claim": "write",
                        }
                        for side in ("before", "after"):
                            if side in w:
                                claim[side] = w[side]
                        claims.append(claim)
                frag["disputes"].append({
                    "position": p, "key": k, "cause": cause, "claims": claims,
                })
                continue
            # 全部覆盖卷都列写且同侧值不矛盾：合成一条精确写
            entry: Dict[str, Any] = {"position": p, "key": k}
            if befores:
                entry["before"] = next(iter(befores.values()))
            if afters:
                entry["after"] = next(iter(afters.values()))
            sources = []
            for vi in covering:
                v, w = volumes[vi], listed[vi]
                src = {"volume_id": v["volume_id"], "range": v["range"]}
                for side in ("before", "after"):
                    if side in w:
                        src[side] = w[side]
                sources.append(src)
            entry["sources"] = sources
            frag["writes"].append(entry)
    frag["writes"].sort(key=lambda e: (e["position"], e["key"]))
    return frag


# --------------------------------------------------------------------------
# 组装案卷与来源清单
# --------------------------------------------------------------------------

def compose(
    settings: dict,
    roster: Dict[str, dict],
    fragments: Dict[str, dict],
    version: int,
    base: Optional[int],
) -> Tuple[dict, dict]:
    """把各组整理结果与独立设定材料组合成案卷 + 来源清单。"""
    writes_out: List[dict] = []
    gaps_out: List[dict] = []
    materials: Dict[str, dict] = {}

    snap = settings.get("snapshot")
    if snap is not None:
        materials[SNAPSHOT_MATERIAL_ID] = {
            "kind": "snapshot",
            "origin": "settings",
            "position": snap.get("position", settings["hi"] - 1),
            "note": "案卷设定自带的终态快照，独立材料原样保留",
        }
    for c in settings.get("checks", []):
        materials[c["id"]] = {
            "kind": "manual_check",
            "origin": "settings",
            "position": c["position"],
            "key": c["key"],
            "note": "案卷设定自带的人工核对单，独立材料原样保留",
        }

    for group in sorted(fragments):
        frag = fragments[group]
        gkeys = list(frag["keys"])
        for u in frag["uncovered"]:
            gid = "%su:%s:%d:%d" % (RESERVED_ID_PREFIX, group, u["a"], u["b"])
            gaps_out.append({"id": gid,
                             "range": {"a": u["a"], "b": u["b"]},
                             "keys": gkeys})
            materials[gid] = {
                "kind": "gap",
                "reason": "no_coverage",
                "group": group,
                "range": {"a": u["a"], "b": u["b"]},
                "keys": gkeys,
                "message": "该边界区间没有任何现行分卷覆盖",
            }
        for d in frag["disputes"]:
            gid = "%sd:%d:%s" % (RESERVED_ID_PREFIX, d["position"], d["key"])
            gaps_out.append({"id": gid,
                             "range": {"a": d["position"],
                                       "b": d["position"] + 1},
                             "keys": [d["key"]]})
            materials[gid] = {
                "kind": "gap",
                "reason": "dispute",
                "position": d["position"],
                "key": d["key"],
                "cause": d["cause"],
                "claims": d["claims"],
                "message": "覆盖该边界的分卷主张不一致；"
                           "争议写及其部分值不交给查询端",
            }
        for w in frag["writes"]:
            wid = "%sw:%d:%s" % (RESERVED_ID_PREFIX, w["position"], w["key"])
            entry = {"id": wid, "position": w["position"], "key": w["key"]}
            for side in ("before", "after"):
                if side in w:
                    entry[side] = w[side]
            writes_out.append(entry)
            materials[wid] = {
                "kind": "write",
                "position": w["position"],
                "key": w["key"],
                "sources": w["sources"],
            }

    writes_out.sort(key=lambda e: (e["position"], e["key"], e["id"]))
    gaps_out.sort(key=lambda e: (e["range"]["a"], e["range"]["b"], e["id"]))
    archive: Dict[str, Any] = {
        "history": {"lo": settings["lo"], "hi": settings["hi"]},
        "keys": list(settings["keys"]),
        "writes": writes_out,
        "gaps": gaps_out,
        "publication": {"version": version},
    }
    if snap is not None:
        archive["snapshot"] = snap
    if settings.get("checks"):
        archive["checks"] = settings["checks"]
    provenance = {
        "version": version,
        "base": base,
        "history": {"lo": settings["lo"], "hi": settings["hi"]},
        "keys": list(settings["keys"]),
        "groups": {g: list(kl) for g, kl in settings["groups"].items()},
        "roster": [
            {"volume_id": vid, "group": m["group"],
             "range": {"a": m["range"]["a"], "b": m["range"]["b"]},
             "sha256": m["sha256"]}
            for vid, m in sorted(roster.items())
        ],
        "materials": materials,
    }
    return archive, provenance


# --------------------------------------------------------------------------
# 发布库
# --------------------------------------------------------------------------

class _PublishLock:
    def __init__(self, store: str):
        self._fd = os.open(os.path.join(store, LOCK_FILE),
                           os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._fd)
            raise PublisherBusy("已有发布进程在进行；一次只支持一名发布者")

    def close(self) -> None:
        os.close(self._fd)


def _clean_stale_temps(store: str) -> None:
    """清理中途终止留下的临时文件/目录（从不被 CURRENT 引用）。"""
    for sub in ("", "volumes", "fragments", "releases"):
        d = os.path.join(store, sub) if sub else store
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if ".tmp-" not in name:
                continue
            path = os.path.join(d, name)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)
            except OSError:
                pass


def _read_current(store: str) -> int:
    try:
        with open(os.path.join(store, CURRENT_FILE), "r",
                  encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError) as exc:
        raise StoreError("无法读取当前版本指针: %s" % exc)


def _load_meta(store: str, version: int) -> dict:
    meta = _read_json(
        os.path.join(store, "releases", "v%d" % version, "meta.json"),
        "版本 v%d 的元数据" % version,
    )
    if (
        not isinstance(meta, dict)
        or meta.get("version") != version
        or not isinstance(meta.get("roster"), dict)
    ):
        raise StoreError("版本 v%d 的元数据损坏" % version)
    return meta


def _load_settings(store: str) -> dict:
    return validate_settings(
        _read_json(os.path.join(store, SETTINGS_FILE), "案卷设定")
    )


def _write_release(store: str, version: int, archive: dict,
                   provenance: dict, meta: dict) -> str:
    """整目录 tmp -> rename 发布；已存在的同名残留（崩溃遗留）先清除。"""
    releases = os.path.join(store, "releases")
    final = os.path.join(releases, "v%d" % version)
    tmp = os.path.join(releases, ".tmp-v%d-%d" % (version, os.getpid()))
    if os.path.lexists(tmp):
        shutil.rmtree(tmp, ignore_errors=True)
    if os.path.isdir(final):
        # CURRENT 未指向它（否则不会走到这里），属上次崩溃的残留
        shutil.rmtree(final, ignore_errors=True)
    os.makedirs(tmp)
    for name, obj in (("archive.json", archive),
                      ("provenance.json", provenance),
                      ("meta.json", meta)):
        with open(os.path.join(tmp, name), "wb") as f:
            data = _pretty(obj)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    _fsync_dir(tmp)
    os.rename(tmp, final)
    _fsync_dir(releases)
    return final


def _group_fragment_hash(group: str, members: List[Tuple[str, str]]) -> str:
    return _sha256(_canonical({"group": group, "volumes": members}))


def _collect_fragments(
    store: str,
    settings: dict,
    new_roster: Dict[str, dict],
    new_volumes: Dict[str, Tuple[dict, str, bytes]],
) -> Tuple[Dict[str, dict], Dict[str, str], List[str], List[str]]:
    """
    逐组取整理结果：内容哈希命中 fragments/ 缓存则直接复用（不读取该组
    原始分卷）；只有内容变化过的组才读取其现行分卷重新归并。
    """
    vol_dir = os.path.join(store, "volumes")
    frag_dir = os.path.join(store, "fragments")
    fragments: Dict[str, dict] = {}
    frag_hashes: Dict[str, str] = {}
    merged_groups: List[str] = []
    reused_groups: List[str] = []
    for g in sorted(settings["groups"]):
        members = sorted(
            (vid, m["sha256"])
            for vid, m in new_roster.items()
            if m["group"] == g
        )
        fh = _group_fragment_hash(g, members)
        frag_hashes[g] = fh
        fpath = os.path.join(frag_dir, fh + ".json")
        if os.path.exists(fpath):
            fragments[g] = _read_json(fpath, "组 %s 的整理结果" % g)
            reused_groups.append(g)
            continue
        vols = []
        for vid, sha in members:
            if vid in new_volumes:
                vols.append(new_volumes[vid][0])
            else:
                vols.append(_read_json(os.path.join(vol_dir, sha + ".json"),
                                       "分卷 %s" % vid))
        frag = merge_group(g, settings["groups"][g], vols,
                           settings["lo"], settings["hi"])
        _write_file_atomic(fpath, _canonical(frag))
        fragments[g] = frag
        merged_groups.append(g)
    return fragments, frag_hashes, merged_groups, reused_groups


# --------------------------------------------------------------------------
# 命令
# --------------------------------------------------------------------------

def cmd_init(store: str, settings_path: str) -> dict:
    if os.path.lexists(store):
        if not os.path.isdir(store) or os.listdir(store):
            raise StoreError("发布库目录已存在且非空: %s" % store)
    settings = validate_settings(_read_json(settings_path, "案卷设定"))
    os.makedirs(store, exist_ok=True)
    for sub in ("volumes", "fragments", "releases"):
        os.makedirs(os.path.join(store, sub), exist_ok=True)
    _write_file_atomic(os.path.join(store, SETTINGS_FILE),
                       _read_raw(settings_path))

    # v0：空分卷名册
    fragments, frag_hashes = {}, {}
    for g in sorted(settings["groups"]):
        frag = merge_group(g, settings["groups"][g], [],
                           settings["lo"], settings["hi"])
        fh = _group_fragment_hash(g, [])
        _write_file_atomic(os.path.join(store, "fragments", fh + ".json"),
                           _canonical(frag))
        fragments[g] = frag
        frag_hashes[g] = fh
    archive, provenance = compose(settings, {}, fragments, 0, None)
    Archive(archive)  # 兜底：保证发布的案卷必然被现有工具接受
    meta = {"version": 0, "base": None, "roster": {},
            "group_fragments": frag_hashes}
    rel = _write_release(store, 0, archive, provenance, meta)
    _write_file_atomic(os.path.join(store, CURRENT_FILE), b"0")
    return {
        "status": "initialized",
        "version": 0,
        "archive": os.path.join(rel, "archive.json"),
        "provenance": os.path.join(rel, "provenance.json"),
    }


def _read_raw(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        raise StoreError("无法读取文件 %s: %s" % (path, exc))


def cmd_publish(store: str, batch_path: str) -> dict:
    if not os.path.isdir(store):
        raise StoreError("发布库不存在: %s" % store)
    lock = _PublishLock(store)
    try:
        _clean_stale_temps(store)
        settings = _load_settings(store)
        version = _read_current(store)
        meta = _load_meta(store, version)
        roster = meta["roster"]

        batch = _read_json(batch_path, "批次文件")
        if not isinstance(batch, dict):
            raise BatchRejected("批次必须为 JSON 对象")
        base = batch.get("base")
        if not _is_int(base):
            raise BatchRejected("批次必须声明整数基版 base")
        if base != version:
            raise BatchRejected(
                "过期基版：批次基于 v%d，当前版本为 v%d；"
                "请基于最新版本重新提交" % (base, version)
            )
        new_roster, new_volumes, summary = apply_batch(
            roster, batch.get("changes"), settings
        )

        # 新卷原始内容落盘（内容寻址、幂等；崩溃残留无害）
        vol_dir = os.path.join(store, "volumes")
        for vid, (vol, sha, data) in new_volumes.items():
            path = os.path.join(vol_dir, sha + ".json")
            if not os.path.exists(path):
                _write_file_atomic(path, data)

        fragments, frag_hashes, merged, reused = _collect_fragments(
            store, settings, new_roster, new_volumes
        )
        archive, provenance = compose(settings, new_roster, fragments,
                                      version + 1, version)
        Archive(archive)  # 兜底：保证发布的案卷必然被现有工具接受
        new_meta = {"version": version + 1, "base": version,
                    "roster": new_roster, "group_fragments": frag_hashes}
        rel = _write_release(store, version + 1, archive, provenance, new_meta)
        # 提交点：原子切换版本指针
        _write_file_atomic(os.path.join(store, CURRENT_FILE),
                           ("%d" % (version + 1)).encode("utf-8"))
        return {
            "status": "published",
            "version": version + 1,
            "base": version,
            "archive": os.path.join(rel, "archive.json"),
            "provenance": os.path.join(rel, "provenance.json"),
            "changes": summary,
            "merged_groups": merged,
            "reused_groups": reused,
            "materials": {"writes": len(archive["writes"]),
                          "gaps": len(archive["gaps"])},
        }
    finally:
        lock.close()


def cmd_current(store: str) -> dict:
    version = _read_current(store)
    rel = os.path.join(store, "releases", "v%d" % version)
    out = {"version": version}
    for name in ("archive.json", "provenance.json", "meta.json"):
        path = os.path.join(rel, name)
        if not os.path.isfile(path):
            raise StoreError("版本 v%d 缺少 %s；发布库损坏" % (version, name))
        out[name.split(".")[0]] = os.path.abspath(path)
    return out


def cmd_status(store: str) -> dict:
    version = _read_current(store)
    meta = _load_meta(store, version)
    return {
        "version": version,
        "volumes": [
            {"volume_id": vid, "group": m["group"],
             "range": m["range"], "sha256": m["sha256"]}
            for vid, m in sorted(meta["roster"].items())
        ],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _fail(payload: dict, code: int) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2), file=sys.stderr)
    return code


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="案卷发布器：把一批分卷变动合入当前版本，产出可直接交给 "
                    "forensic_query.py 查询的案卷与来源清单。"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="用固定案卷设定初始化发布库（产生空名册 v0）")
    p_init.add_argument("store", help="发布库目录")
    p_init.add_argument("--settings", required=True, help="案卷设定 JSON 文件")
    p_pub = sub.add_parser("publish", help="提交一批分卷变动，发布新版本")
    p_pub.add_argument("store", help="发布库目录")
    p_pub.add_argument("--batch", required=True, help="批次 JSON 文件")
    p_cur = sub.add_parser("current", help="输出当前版本号及案卷/来源清单路径（读者入口）")
    p_cur.add_argument("store", help="发布库目录")
    p_st = sub.add_parser("status", help="输出当前版本与现行卷名册")
    p_st.add_argument("store", help="发布库目录")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "init":
            out = cmd_init(args.store, args.settings)
        elif args.cmd == "publish":
            out = cmd_publish(args.store, args.batch)
        elif args.cmd == "current":
            out = cmd_current(args.store)
        else:
            out = cmd_status(args.store)
    except BatchRejected as exc:
        return _fail({"rejected": str(exc)}, 2)
    except StructuralError as exc:
        return _fail({"structural_error": str(exc)}, 2)
    except PublisherBusy as exc:
        return _fail({"busy": str(exc)}, 3)
    except (StoreError, OSError) as exc:
        return _fail({"store_error": str(exc)}, 1)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

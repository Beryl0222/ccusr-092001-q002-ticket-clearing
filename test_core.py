"""核心领域引擎测试：覆盖可信核验、离线两阶段、重复补贴防护、
复核队列、可复算清算与哈希链完整性。"""

import json
import os
import unittest
from datetime import datetime

from core import (DomainConfig, ClearingService, Store, DomainError, TZ,
                  RESULT_VALID, RESULT_PENDING_REVIEW, RESULT_REVOKED,
                  RESULT_SETTLED, DECISION_VALID, DECISION_DUPLICATE,
                  DECISION_REVIEW, DECISION_REVOKED, REVIEW_OPEN,
                  build_order_independence_fixture, sign_payload,
                  canonical_json, sha256_hex)

HERE = os.path.dirname(os.path.abspath(__file__))
MATCH = "M-2026-001"
KICKOFF = "2026-05-15T19:30:00+08:00"
ISSUER_SECRET = "unit-issuer"
DEVICE_SECRET = "unit-device"
DEVICE = "DEV-001"
SPOT = "S001"          # A 组（山水生态，周结，三类票通用）
SPOT_B = "S013"        # B 组（文博，月结，不接受团体票）


class MutableClock:
    def __init__(self, dt: datetime):
        self.dt = dt

    def __call__(self) -> datetime:
        return self.dt

    def set(self, dt: datetime):
        self.dt = dt


class ServiceTestBase(unittest.TestCase):
    now = datetime(2026, 5, 16, 12, 0, tzinfo=TZ)

    def setUp(self):
        self.cfg = DomainConfig.load(os.path.join(HERE, "domain.json"))
        self.clock = MutableClock(self.now)
        self.store = Store(":memory:", clock=self.clock)
        self.svc = ClearingService(self.cfg, self.store,
                                   issuer_secret=ISSUER_SECRET,
                                   device_secrets={DEVICE: DEVICE_SECRET},
                                   clock=self.clock)
        self.svc.register_match(MATCH, KICKOFF)
        self.svc.register_device(DEVICE, DEVICE_SECRET, SPOT, "阳明山闸机")

    def issue(self, code="T001", ttype="纸质票根", holder="张三",
              face=80):
        r = self.svc.issue_ticket(code, ttype, holder, MATCH, face)
        return r

    def offline_record(self, rid, ticket, holder, ttype, event_at,
                       spot=SPOT, device=DEVICE, secret=DEVICE_SECRET,
                       match=MATCH, site="阳明山闸机"):
        body, sig = ClearingService.build_offline_record(
            secret, device, rid, ticket, holder, ttype, spot, match,
            site, event_at)
        body["record_sig"] = sig
        return body

    def manifest(self, records, device=DEVICE, secret=DEVICE_SECRET,
                 mid="MF-T1"):
        keys = sorted(r["record_id"] for r in records)
        return {"manifest_id": mid, "device_id": device, "record_ids": keys,
                "keys_sig": sign_payload(
                    secret, {"device_id": device, "record_ids": keys})}

    def upload(self, records, mf=None):
        return self.svc.upload_offline(records, mf or self.manifest(records))


class DomainConfigTest(unittest.TestCase):
    def setUp(self):
        self.cfg = DomainConfig.load(os.path.join(HERE, "domain.json"))

    def test_约定口径保持不变(self):
        self.assertEqual(self.cfg.raw["票种"],
                         ["实名电子票", "纸质票根", "团体票"])
        self.assertEqual(self.cfg.raw["核销结果"],
                         ["有效", "待补传", "待复核", "已撤销", "已清算"])
        self.assertEqual(self.cfg.raw["结算周期"], ["周结", "月结"])

    def test_四十二家景区与四个分组(self):
        self.assertEqual(self.cfg.check(), [])
        self.assertEqual(len(self.cfg.spots), 42)
        self.assertEqual(set(self.cfg.group_cadence.values()),
                         {"周结", "月结"})


class OnlineRedeemTest(ServiceTestBase):
    def test_可信核验全要素通过(self):
        t = self.issue()
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根")
        self.assertEqual(r["result"], RESULT_VALID)
        self.assertEqual(len(self.svc._rights_snapshot()["valid_rights"]), 1)

    def test_伪造票根签名被拒(self):
        self.issue()
        with self.assertRaises(DomainError) as cx:
            self.svc.redeem_online("T001", "deadbeef", SPOT,
                                   "张三", "纸质票根")
        self.assertEqual(cx.exception.code, "BAD_TICKET_SIGNATURE")

    def test_持票人不符进入复核而非直接放行(self):
        t = self.issue()
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "李四", "纸质票根")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        self.assertIn("持票人与票根登记不一致", r["review_reasons"])
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 0)

    def test_票种不在分组适用范围进入复核(self):
        # 团体票不适用于 B 组文博场馆
        self.svc.register_device("DEV-B", "sb", SPOT_B, "柳子庙闸机")
        t = self.issue("TG1", "团体票", "某旅行团", face=200)
        r = self.svc.redeem_online("TG1", t["signature"], SPOT_B,
                                   "某旅行团", "团体票")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        self.assertTrue(any("分组B" in x for x in r["review_reasons"]))

    def test_每景区一次_累计三景区_上限(self):
        t = self.issue()
        for spot in ("S001", "S002", "S003"):
            r = self.svc.redeem_online("T001", t["signature"], spot,
                                       "张三", "纸质票根")
            self.assertEqual(r["result"], RESULT_VALID, spot)
        # 第 4 个景区 → 待复核
        r = self.svc.redeem_online("T001", t["signature"], "S004",
                                   "张三", "纸质票根")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        self.assertTrue(any("上限" in x for x in r["review_reasons"]))
        # 同一景区再来一次 → 同样入复核，不产生第二笔
        r = self.svc.redeem_online("T001", t["signature"], "S001",
                                   "张三", "纸质票根")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 3)

    def test_场次窗口与取消(self):
        t = self.issue()
        # 窗口外（开赛 5/15 19:30，赛前 72h 起；5/1 太早）
        self.clock.set(datetime(2026, 5, 1, 12, 0, tzinfo=TZ))
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        # 场次取消后核验
        self.clock.set(self.now)
        self.svc.cancel_match(MATCH)
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        self.assertIn("所属场次已取消", r["review_reasons"])

    def test_时钟偏差超容忍进入复核(self):
        t = self.issue()
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根",
                                   event_at="2026-05-16T12:10:00+08:00")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        self.assertTrue(any("时钟" in x for x in r["review_reasons"]))


class OfflineTest(ServiceTestBase):
    event_at = "2026-05-16T11:58:00+08:00"

    def test_离线签名记录补传后有效(self):
        self.issue()
        rec = self.offline_record("R1", "T001", "张三", "纸质票根", self.event_at)
        out = self.upload([rec])
        self.assertEqual(out["decisions"][0]["decision"], DECISION_VALID)
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 1)

    def test_批内同票同景区重复只占一次权益(self):
        self.issue()
        recs = [self.offline_record("R1", "T001", "张三", "纸质票根",
                                    self.event_at),
                self.offline_record("R2", "T001", "张三", "纸质票根",
                                    "2026-05-16T11:59:00+08:00")]
        out = self.upload(recs)
        ds = {d["record_id"]: d["decision"] for d in out["decisions"]}
        self.assertEqual(ds, {"R1": DECISION_VALID, "R2": DECISION_DUPLICATE})
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 1)

    def test_整批重放与乱序分片到达结果一致(self):
        self.issue("T001"), self.issue("T002", holder="李四")
        recs = [self.offline_record("R1", "T001", "张三", "纸质票根",
                                    self.event_at),
                self.offline_record("R2", "T002", "李四", "纸质票根",
                                    self.event_at)]
        mf = self.manifest(recs)
        # 先到一半（清单允许分片），再补齐，再整批重放
        self.upload([recs[0]], mf)
        out = self.upload(recs, mf)
        self.assertEqual({d["decision"] for d in out["decisions"]},
                         {DECISION_DUPLICATE, DECISION_VALID})
        replay = self.svc.upload_offline(list(reversed(recs)), mf)
        self.assertTrue(all(d["decision"] == DECISION_DUPLICATE
                            for d in replay["decisions"]))
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 2)

    def test_跨渠道线上线下只产生一次权益(self):
        t = self.issue()
        self.assertEqual(self.svc.redeem_online(
            "T001", t["signature"], SPOT, "张三", "纸质票根")["result"],
            RESULT_VALID)
        rec = self.offline_record("R1", "T001", "张三", "纸质票根",
                                  self.event_at)
        out = self.upload([rec])
        self.assertEqual(out["decisions"][0]["decision"], DECISION_DUPLICATE)

    def test_伪造记录与越清单记录被整批拒绝(self):
        self.issue()
        good = self.offline_record("R1", "T001", "张三", "纸质票根",
                                   self.event_at)
        forged = dict(good)
        forged["record_id"] = "R9"
        forged["holder"] = "伪造者"
        # R9 在清单里但签名对不上
        with self.assertRaises(DomainError) as cx:
            self.upload([forged])
        self.assertEqual(cx.exception.code, "BAD_RECORD_SIGNATURE")
        # 篡改清单签名
        bad_mf = dict(self.manifest([good]))
        bad_mf["keys_sig"] = "0" * 64
        with self.assertRaises(DomainError) as cx:
            self.svc.upload_offline([good], bad_mf)
        self.assertEqual(cx.exception.code, "BAD_MANIFEST_SIGNATURE")
        # 无权益落库
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 0)

    def test_设备只能为绑定景区上报(self):
        self.issue()
        rec = self.offline_record("R1", "T001", "张三", "纸质票根",
                                  self.event_at, spot="S002")
        out = self.upload([rec])
        self.assertEqual(out["decisions"][0]["decision"], DECISION_REVIEW)
        self.assertTrue(any("绑定景区" in x
                            for x in out["decisions"][0]["review_reasons"]))

    def test_时钟超前与超过闭合时限进入复核(self):
        self.issue()
        # 设备时钟超前 1 小时
        rec = self.offline_record("R1", "T001", "张三", "纸质票根",
                                  "2026-05-16T13:00:00+08:00")
        out = self.upload([rec])
        self.assertEqual(out["decisions"][0]["decision"], DECISION_REVIEW)
        # 25 小时后补传：超过 24h 闭合时限
        rec2 = self.offline_record("R2", "T001", "张三", "纸质票根",
                                   "2026-05-15T11:00:00+08:00")
        out = self.upload([rec2], self.manifest([rec2], mid="MF-T2"))
        self.assertEqual(out["decisions"][0]["decision"], DECISION_REVIEW)
        self.assertTrue(any("闭合时限" in x
                            for x in out["decisions"][0]["review_reasons"]))


class AntiDoubleSubsidyTest(ServiceTestBase):
    event_at = "2026-05-16T11:58:00+08:00"

    def test_退款冲抵且重复退款幂等(self):
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        ref = self.svc.refund_ticket("T001")
        self.assertEqual(len(ref["adjustments"]), 1)
        self.assertEqual(ref["adjustments"][0]["amount_fen"], -3000)
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 0)
        with self.assertRaises(DomainError) as cx:
            self.svc.refund_ticket("T001")
        self.assertEqual(cx.exception.code, "ALREADY_REFUNDED")

    def test_退款后离线补传不得复活权益(self):
        self.issue()
        self.svc.refund_ticket("T001")
        rec = self.offline_record("R1", "T001", "张三", "纸质票根",
                                  self.event_at)
        out = self.upload([rec])
        self.assertEqual(out["decisions"][0]["decision"], DECISION_REVOKED)
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 0)

    def test_场次取消冲抵且补传置撤销(self):
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        out = self.svc.cancel_match(MATCH)
        self.assertEqual(out["adjustments"][0]["amount_fen"], -3000)
        rec = self.offline_record("R1", "T001", "张三", "纸质票根",
                                  self.event_at)
        d = self.upload([rec])["decisions"][0]
        self.assertEqual(d["decision"], DECISION_REVOKED)

    def test_场次延期_窗口外冲抵_窗口内保留(self):
        # 窗口外：延期到 9 月
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        out = self.svc.postpone_match(MATCH, "2026-09-01T19:30:00+08:00")
        self.assertEqual(len(out["adjustments"]), 1)
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 0)

    def test_场次延期窗口内不冲抵(self):
        # 新开赛 5/16 10:00，核销 5/16 12:00 在新窗口（赛前72h~赛后168h）内
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        out = self.svc.postpone_match(MATCH, "2026-05-16T10:00:00+08:00")
        self.assertEqual(out["adjustments"], [])
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 1)

    def test_人工撤销不可重复(self):
        t = self.issue()
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根")
        out = self.svc.manual_revoke(r["redemption_id"], "现场核错")
        self.assertEqual(out["adjustments"][0]["amount_fen"], -3000)
        with self.assertRaises(DomainError) as cx:
            self.svc.manual_revoke(r["redemption_id"], "再次撤销")
        self.assertEqual(cx.exception.code, "ALREADY_REVOKED")


class ReviewQueueTest(ServiceTestBase):
    def test_异常入队_通过后补占权益(self):
        t = self.issue()
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根",
                                   event_at="2026-05-16T12:06:00+08:00")
        self.assertEqual(r["result"], RESULT_PENDING_REVIEW)
        cases = self.svc.list_reviews()
        self.assertEqual(len(cases), 1)
        out = self.svc.resolve_review(cases[0]["id"], True, "复核员/甲",
                                      "设备时钟已校准")
        self.assertEqual(out["decision"], "approved_valid")
        self.assertEqual(self.svc._rights_snapshot()["total_valid"], 1)

    def test_驳回置撤销_已退款票不得通过补占(self):
        t = self.issue()
        r = self.svc.redeem_online("T001", t["signature"], SPOT,
                                   "张三", "纸质票根",
                                   event_at="2026-05-16T12:06:00+08:00")
        rid = r["redemption_id"]
        case = self.svc.list_reviews()[0]
        self.svc.refund_ticket("T001")
        out = self.svc.resolve_review(case["id"], True, "复核员/甲")
        self.assertEqual(out["decision"], "approved_unbindable")
        row = self.store.query_one(
            "SELECT result FROM redemptions WHERE id=?", (rid,))
        self.assertEqual(row["result"], RESULT_REVOKED)
        # 已裁决不可重复处理
        with self.assertRaises(DomainError) as cx:
            self.svc.resolve_review(case["id"], False, "复核员/乙")
        self.assertEqual(cx.exception.code, "REVIEW_CLOSED")


class SettlementTest(ServiceTestBase):
    def seal(self, kind, start, spot=SPOT):
        return self.svc.seal_batch(kind, start, spot)

    def test_周结封账与复算(self):
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        self.clock.set(datetime(2026, 5, 18, 10, 0, tzinfo=TZ))
        b = self.seal("周结", "2026-05-11T00:00:00+08:00")
        self.assertEqual((b["count"], b["gross_fen"], b["net_fen"]),
                         (1, 3000, 3000))
        self.assertTrue(b["snapshot_hash"])
        rc = self.svc.recompute_batch(b["batch_id"])
        self.assertTrue(rc["recomputable"])
        # 重复封账被拒
        with self.assertRaises(DomainError) as cx:
            self.seal("周结", "2026-05-11T00:00:00+08:00")
        self.assertEqual(cx.exception.code, "ALREADY_SEALED")
        row = self.store.query_one(
            "SELECT result FROM redemptions WHERE id=1")
        self.assertEqual(row["result"], RESULT_SETTLED)

    def test_周期未结束与口径不符拒绝封账(self):
        with self.assertRaises(DomainError) as cx:
            self.seal("周结", "2026-05-11T00:00:00+08:00")
        self.assertEqual(cx.exception.code, "PERIOD_OPEN")
        self.clock.set(datetime(2026, 5, 18, 10, 0, tzinfo=TZ))
        with self.assertRaises(DomainError) as cx:
            self.seal("月结", "2026-05-01T00:00:00+08:00")
        self.assertEqual(cx.exception.code, "CADENCE_MISMATCH")

    def test_迟来事项滚入下一开放周期(self):
        # 周一（5/18）上午先封上一周，周日深夜的离线记录当晚才补传
        self.issue()
        rec = self.offline_record("R1", "T001", "张三", "纸质票根",
                                  "2026-05-17T22:00:00+08:00")
        self.clock.set(datetime(2026, 5, 18, 9, 0, tzinfo=TZ))
        b1 = self.seal("周结", "2026-05-11T00:00:00+08:00")
        self.assertEqual(b1["count"], 0)
        self.clock.set(datetime(2026, 5, 18, 18, 0, tzinfo=TZ))
        self.upload([rec])
        self.clock.set(datetime(2026, 5, 25, 10, 0, tzinfo=TZ))
        b2 = self.seal("周结", "2026-05-18T00:00:00+08:00")
        self.assertEqual(b2["count"], 1)
        self.assertEqual(b2["net_fen"], 3000)
        self.assertTrue(self.svc.recompute_batch(b2["batch_id"])["recomputable"])

    def test_已封账后退款只冲抵不改账(self):
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        self.clock.set(datetime(2026, 5, 18, 10, 0, tzinfo=TZ))
        b1 = self.seal("周结", "2026-05-11T00:00:00+08:00")
        # 下一周退款：原批次净额不变，调整单挂入下一周
        self.clock.set(datetime(2026, 5, 19, 10, 0, tzinfo=TZ))
        ref = self.svc.refund_ticket("T001")
        self.assertEqual(ref["adjustments"][0]["amount_fen"], -3000)
        self.assertEqual(self.svc.recompute_batch(b1["batch_id"])["stored"]
                         ["net_fen"], 3000)
        self.clock.set(datetime(2026, 5, 25, 10, 0, tzinfo=TZ))
        b2 = self.seal("周结", "2026-05-18T00:00:00+08:00")
        self.assertEqual(b2["count"], 0)
        self.assertEqual(b2["net_fen"], -3000)

    def test_顺序封账约束(self):
        # 人为建出更早的开放批次（先不封 5/11 周，直接封 5/18 周）
        self.clock.set(datetime(2026, 5, 25, 10, 0, tzinfo=TZ))
        self.svc._ensure_batch(
            "周结", datetime(2026, 5, 11, tzinfo=TZ), SPOT)
        with self.assertRaises(DomainError) as cx:
            self.seal("周结", "2026-05-18T00:00:00+08:00")
        self.assertEqual(cx.exception.code, "OUT_OF_ORDER_SEAL")

    def test_月结景区按自然月清算(self):
        self.svc.register_device("DEV-B", "sb", SPOT_B, "柳子庙闸机")
        t = self.issue("TE1", "实名电子票", "王五", face=120)
        self.svc.redeem_online("TE1", t["signature"], SPOT_B,
                               "王五", "实名电子票")
        self.clock.set(datetime(2026, 6, 2, 10, 0, tzinfo=TZ))
        b = self.seal("月结", "2026-05-01T00:00:00+08:00", spot=SPOT_B)
        self.assertEqual((b["count"], b["net_fen"]), (1, 5000))
        self.assertTrue(self.svc.recompute_batch(b["batch_id"])["recomputable"])


class LedgerTest(ServiceTestBase):
    def test_哈希链完整且篡改即断链(self):
        t = self.issue()
        self.svc.redeem_online("T001", t["signature"], SPOT,
                               "张三", "纸质票根")
        self.assertTrue(self.store.verify_chain()["ok"])
        # 直接篡改底层载荷
        self.store.conn.execute(
            "UPDATE event_log SET payload=? WHERE seq=2",
            (canonical_json({"tampered": True}),))
        verdict = self.store.verify_chain()
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["broken_at_seq"], 2)


class OrderIndependenceProofTest(unittest.TestCase):
    def setUp(self):
        self.cfg = DomainConfig.load(os.path.join(HERE, "domain.json"))
        self.fixture = build_order_independence_fixture(self.cfg)

    def _fresh(self):
        from core import _build_proof_service
        svc = _build_proof_service(self.cfg, self.fixture)
        for t in self.fixture["tickets"]:
            svc.issue_ticket(**t)
        for m in self.fixture["matches"]:
            svc.register_match(**m)
        return svc

    def _digest(self, svc):
        return sha256_hex(canonical_json(svc._rights_snapshot()).encode())

    def test_原序逆序洗牌分片重放同一结果(self):
        records = self.fixture["records"]
        orders = {
            "原序": records,
            "逆序": list(reversed(records)),
            "洗牌": [records[i] for i in self.fixture["shuffle"]],
        }
        digests = {}
        for name, recs in orders.items():
            svc = self._fresh()
            svc.upload_offline(recs, self.fixture["manifest"])
            digests[name] = self._digest(svc)
        # 分片：先 1 条，再 3 条，再全量
        svc = self._fresh()
        svc.upload_offline(records[:1], self.fixture["manifest"])
        svc.upload_offline(records[1:4], self.fixture["manifest"])
        svc.upload_offline(records, self.fixture["manifest"])
        digests["分片重放"] = self._digest(svc)
        self.assertEqual(len(set(digests.values())), 1, digests)
        snap = svc._rights_snapshot()
        # 4 张有效（R4 与 R2 同票同景区被去重），1 张票种不符在复核
        self.assertEqual(snap["total_valid"], 4)
        self.assertEqual(len(snap["pending_review"]), 1)

    def test_证明接口结论(self):
        svc = ClearingService(self.cfg, Store(":memory:"),
                              issuer_secret=self.fixture["issuer_secret"])
        proof = svc.prove_order_independence(self.fixture)
        self.assertTrue(proof["identical"])
        self.assertEqual(len(set(proof["digests"].values())), 1)


if __name__ == "__main__":
    unittest.main()

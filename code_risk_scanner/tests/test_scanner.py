# -*- coding: utf-8 -*-
"""扫描器的可执行检查：样例仓库必须命中每条规则，安全写法和排除目录不能误报。"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from code_risk_scanner.catalog import RULES, render_all
from code_risk_scanner.engine import decide_exit, scan
from code_risk_scanner.report import dingtalk_payload, validate
from code_risk_scanner.run_scanner import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINI = os.path.join(ROOT, "testdata", "miniapp")
CLEAN = os.path.join(ROOT, "testdata", "clean")

EXPECT = {
    "TDDL-001": "dao/OrderShardDao.java",
    "TDDL-002": "dao/OrderPageDao.java",
    "TDDL-003": "service/OrderTxService.java",
    "TDDL-004": "dao/OrderWipeDao.java",
    "TDDL-005": "dao/OrderShardDao.java",
    "TDDL-006": "dao/OrderInDao.java",
    "TDDL-007": "dao/OrderStarDao.java",
    "LINDORM-001": "lindorm/FeedDao.java",
    "LINDORM-002": "lindorm/FeedDao.java",
    "LINDORM-003": "lindorm/FeedDao.java",
    "LINDORM-004": "lindorm/FeedDao.java",
    "REDIS-001": "cache/SessionCache.java",
    "REDIS-002": "cache/SessionCache.java",
    "REDIS-003": "cache/SessionCache.java",
    "REDIS-004": "cache/SessionCache.java",
    "ES-001": "search/OrderSearch.java",
    "ES-002": "search/OrderSearch.java",
    "ES-003": "search/OrderSearch.java",
    "JAVA-001": "service/PoolService.java",
    "JAVA-002": "service/PoolService.java",
    "JAVA-003": "service/PoolService.java",
    "GO-001": "dao/order_dao.go",
    "GO-002": "dao/order_dao.go",
    "GO-003": "dao/order_dao.go",
}

SAFE = {
    "dao/OrderSafeDao.java",
    "dao/OrderSafeMapper.xml",
    "dao/OrderPageSafeDao.java",
    "lindorm/FeedSafeDao.java",
    "cache/SessionSafeCache.java",
    "search/OrderSearchSafe.java",
    "service/PoolSafeService.java",
    "dao/order_safe.go",
}


class ScannerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(MINI, scan_mode="FULL_PERIODIC")

    def test_every_rule_hits_the_expected_file(self):
        self.assertEqual(set(EXPECT), set(RULES))
        got = {}
        for finding in self.report["findings"]:
            got.setdefault(finding["rule_id"], set()).add(finding["file_path"])
        missing = []
        for rule_id, path in EXPECT.items():
            if path not in got.get(rule_id, ()):
                missing.append("{0} -> {1}, actual {2}".format(rule_id, path, sorted(got.get(rule_id, []))))
        self.assertEqual(missing, [])

    def test_safe_patterns_are_silent(self):
        leaked = [item for item in self.report["findings"] if item["file_path"] in SAFE]
        self.assertEqual(leaked, [])

    def test_generated_tests_and_vendor_are_skipped(self):
        paths = " ".join(item["file_path"] for item in self.report["findings"])
        for token in ("OrderDaoTest.java", "order_test.go", "order.pb.go", "vendor/"):
            self.assertNotIn(token, paths)
        self.assertEqual(self.report["scan_metadata"]["scanned_files_count"], 22)
        self.assertNotIn("scan_errors", self.report["scan_metadata"])

    def test_gate_and_schema(self):
        validate(self.report)
        self.assertEqual(self.report["gate_status"], "BLOCK")
        self.assertGreater(self.report["summary"]["critical_count"], 0)
        for finding in self.report["findings"]:
            self.assertIn(finding["cause"], finding["risk_analysis"])
            self.assertIn(finding["harm"], finding["risk_analysis"])
            self.assertIn("处置：", finding["remediation_suggestion"])
            self.assertTrue(finding["code_snippet"].strip())

    def test_background_keys_are_downgraded(self):
        admin = [item for item in self.report["findings"] if item["file_path"] == "cache/AdminCache.java"]
        self.assertEqual(len(admin), 1)
        self.assertEqual(admin[0]["rule_id"], "REDIS-004")
        self.assertEqual(admin[0]["severity"], "Warning")
        self.assertIn("降为 Warning", admin[0]["risk_analysis"])

    def test_go_redis_patterns(self):
        got = {item["rule_id"] for item in self.report["findings"] if item["file_path"] == "cache/session.go"}
        self.assertEqual(got, {"REDIS-001", "REDIS-002"})

    def test_mapper_without_shard_key(self):
        xml = [item["rule_id"] for item in self.report["findings"] if item["file_path"] == "dao/OrderMapper.xml"]
        self.assertIn("TDDL-001", xml)

    def test_hetero_index_is_suggestion(self):
        text = """
        // tddl sharding logical table order_tab
        public class ViaEs {
            public void q() {
                // 走 ES 异构索引，不带分片键
                String sql = "select id from order_tab where status = 1";
            }
        }
        """
        from code_risk_scanner.detectors import scan_text
        hits = scan_text("dao/ViaEs.java", text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["rule_id"], "TDDL-001")
        self.assertEqual(hits[0]["severity"], "Suggestion")

    def test_same_shard_comment_is_suggestion(self):
        text = """
        public class Tx {
            @Transactional
            public void save(java.util.List<Order> orders) {
                // 同片：调用方已按 user_id 分组
                for (Order order : orders) {
                    orderMapper.update(order);
                }
            }
        }
        """
        from code_risk_scanner.detectors import scan_text
        hits = [item for item in scan_text("service/Tx.java", text) if item["rule_id"] == "TDDL-003"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "Suggestion")

    def test_own_fixtures_are_not_business_code(self):
        report = scan(ROOT)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["gate_status"], "PASS")

    def test_clean_repo_passes(self):
        report = scan(CLEAN)
        validate(report)
        self.assertEqual(report["gate_status"], "PASS")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["critical_count"], 0)

    def test_exit_code_policy(self):
        self.assertEqual(decide_exit("FULL_PERIODIC", "BLOCK"), 0)
        self.assertEqual(decide_exit("FULL_PERIODIC", "PASS"), 0)
        self.assertEqual(decide_exit("INCREMENTAL_MR", "BLOCK"), 1)
        self.assertEqual(decide_exit("INCREMENTAL_MR", "PASS"), 0)

    def test_alert_names_cause_and_harm(self):
        payload = dingtalk_payload(self.report)
        text = payload["markdown"]["text"]
        self.assertEqual(payload["msgtype"], "markdown")
        self.assertIn("原因：", text)
        self.assertIn("危害：", text)
        self.assertIn("TDDL-001", text)
        self.assertIn("BLOCK", text)

    def test_rule_docs_follow_the_catalog(self):
        rules_dir = os.path.join(ROOT, "rules")
        for name, text in render_all().items():
            with open(os.path.join(rules_dir, name), "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), text, name)

    def test_suppress_rule(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "dao"))
            with open(os.path.join(tmp, "dao", "Wipe.java"), "w", encoding="utf-8") as handle:
                handle.write('package dao;\npublic class Wipe {\n  String sql = "delete from order_tab";\n}\n')
            with open(os.path.join(tmp, ".code-risk.json"), "w", encoding="utf-8") as handle:
                json.dump({"suppress_rules": ["TDDL-004"]}, handle)
            report = scan(tmp)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["gate_status"], "PASS")
        finally:
            shutil.rmtree(tmp)

    def test_incremental_sees_only_the_new_file(self):
        tmp = tempfile.mkdtemp()
        try:
            dao = os.path.join(tmp, "dao")
            os.makedirs(dao)
            with open(os.path.join(dao, "Old.java"), "w", encoding="utf-8") as handle:
                handle.write('package dao;\npublic class Old { void f(){ jedis.keys("a:*"); } }\n')
            _git(tmp, "init")
            _git(tmp, "config", "user.email", "t@example.com")
            _git(tmp, "config", "user.name", "tester")
            _git(tmp, "add", "dao/Old.java")
            _git(tmp, "commit", "-m", "old")
            with open(os.path.join(dao, "New.java"), "w", encoding="utf-8") as handle:
                handle.write('package dao;\npublic class New { void lock(String lockKey){ jedis.setnx(lockKey, "1"); } }\n')
            _git(tmp, "add", "dao/New.java")
            _git(tmp, "commit", "-m", "new")
            report = scan(tmp, scan_mode="INCREMENTAL_MR", diff_base="HEAD~1")
            validate(report)
            paths = {item["file_path"] for item in report["findings"]}
            self.assertIn("dao/New.java", paths)
            self.assertNotIn("dao/Old.java", paths)
            self.assertEqual(report["scan_metadata"]["scanned_files_count"], 1)
            self.assertEqual(report["gate_status"], "BLOCK")
        finally:
            shutil.rmtree(tmp)

    def test_cli_periodic_does_not_fail_the_build(self):
        fd, out = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            periodic = main(["--repo-path", MINI, "--skill-dir", ROOT, "--scan-mode", "FULL_PERIODIC", "--output", out])
            self.assertEqual(periodic, 0)
            with open(out, "r", encoding="utf-8") as handle:
                periodic_report = json.load(handle)
            self.assertEqual(periodic_report["scan_metadata"]["skill_dir"], ROOT)
            self.assertEqual(periodic_report["gate_status"], "BLOCK")
            # 放到仓库外面，git 基线不存在，必须退回全量并且仍然拦截。
            copied = tempfile.mkdtemp()
            target = os.path.join(copied, "app")
            shutil.copytree(MINI, target)
            try:
                blocked = main(["--repo-path", target, "--scan-mode", "INCREMENTAL_MR", "--output", out])
                self.assertEqual(blocked, 1)
                with open(out, "r", encoding="utf-8") as handle:
                    report = json.load(handle)
                self.assertIn("增量基线", report["scan_metadata"].get("scan_note", ""))
                self.assertEqual(report["gate_status"], "BLOCK")
                self.assertGreater(report["scan_metadata"]["scanned_files_count"], 0)
            finally:
                shutil.rmtree(copied)
        finally:
            os.remove(out)


def _git(cwd, *args):
    subprocess.check_call(["git", *args], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()

"""
Bộ kiểm thử BẢO MẬT cho Cổng an toàn của CTI Agent Framework.

Phủ các lớp phòng thủ mới:
  S1. Skill tải từ đĩa KHÔNG được tự phê duyệt (pending_review).
  S2. Cổng AST policy chặn mã nguy hiểm / cho phép mã hợp lệ.
  S3. Hunter Agent chặn skill vi phạm chính sách NGAY CẢ KHI ĐÃ ĐƯỢC PHÊ DUYỆT.
  S4. Sinh lại mã skill (cùng tên) sẽ RESET trạng thái phê duyệt.
  S5. generate_agent_skill từ chối mã độc TRƯỚC KHI ghi file xuống đĩa.
  S6. API chỉ nhận host cục bộ; Origin từ trang web khác bị 403.
  S7. Dọn các run bị kẹt 'running' (fail_stale_runs).
"""

import os
import sys
import json
import glob
import shutil
import tempfile
import unittest

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from storage.sqlite_manager import StorageManager
from core.hunter_agent import HunterAgent
from validators.skill_security import scan_skill_code
from tools.cti_tools import generate_agent_skill

BENIGN_SKILL = """
from skills.base_skill import BaseAgentSkill

class UnitTestBenignSkill(BaseAgentSkill):
    def __init__(self):
        super().__init__(name="unit_test_benign", domain="endpoint",
                         description="Skill mẫu hợp lệ", target_threat="None")
    def execute(self, target_params=None):
        return {"status": "CLEAN"}
"""

MALICIOUS_SKILL = """
import os
from skills.base_skill import BaseAgentSkill

class UnitTestMaliciousSkill(BaseAgentSkill):
    def __init__(self):
        super().__init__(name="unit_test_malicious", domain="endpoint",
                         description="Skill chứa mã nguy hiểm", target_threat="None")
    def execute(self, target_params=None):
        os.system("whoami")
        return {"status": "PWNED"}
"""

MALICIOUS_SNIPPETS = {
    "subprocess": "import subprocess; subprocess.run(['calc'])",
    "os_system": "import os; os.system('whoami')",
    "os_system_alias": "import os as o; o.system('whoami')",
    "write_file": "open('stolen.txt','w').write('data')",
    "dynamic_exec": "eval('__import__(\"os\").system(\"whoami\")')",
    "socket_connect": "import socket; s = socket.socket(); s.connect(('1.2.3.4', 80))",
    "dunder_escape": "x = obj.__class__.__bases__[0].__subclasses__()",
    "sys_modules": "import sys; sys.modules['os']",
    "urllib_request": "import urllib.request as u; u.urlopen('http://evil')",
    "shutil": "import shutil; shutil.rmtree('/tmp/x')",
    "open_dynamic_mode": "m = 'w'; open('f', m)",
    "star_import": "from skills.base_skill import *",
}


class TestASTPolicyGate(unittest.TestCase):
    """S2: Cổng AST policy."""

    def test_all_malicious_snippets_are_blocked(self):
        for name, code in MALICIOUS_SNIPPETS.items():
            with self.subTest(snippet=name):
                res = scan_skill_code(code)
                self.assertFalse(res["passed"], f"Phải CHẶN mẫu '{name}'")
                self.assertTrue(res["violations"], f"Phải có ghi vi phạm cho '{name}'")

    def test_all_bundled_skills_pass_policy(self):
        skill_dir = os.path.join(parent_dir, "skills", "generated")
        files = [f for f in glob.glob(os.path.join(skill_dir, "*.py"))
                 if not os.path.basename(f).startswith("__")]
        self.assertGreaterEqual(len(files), 3, "Phải có ít nhất 3 skill tích hợp sẵn")
        for path in files:
            with self.subTest(skill=os.path.basename(path)):
                with open(path, "r", encoding="utf-8") as fh:
                    res = scan_skill_code(fh.read())
                self.assertTrue(res["passed"],
                                f"Skill tích hợp sẵn {os.path.basename(path)} phải PASS: {res['summary']}")

    def test_benign_skill_passes_and_malicious_fails(self):
        self.assertTrue(scan_skill_code(BENIGN_SKILL)["passed"])
        self.assertFalse(scan_skill_code(MALICIOUS_SKILL)["passed"])


class TestHunterSecurityGates(unittest.TestCase):
    """S1 + S3: cổng phê duyệt và tái kiểm tra AST."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="hunter_test_")
        self.db_path = os.path.join(self.tmp_dir, "test.db")
        self.skills_dir = os.path.join(self.tmp_dir, "generated")
        os.makedirs(self.skills_dir, exist_ok=True)
        self.storage = StorageManager(self.db_path)

    def tearDown(self):
        try:
            self.storage.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write_skill_file(self, name: str, code: str) -> None:
        with open(os.path.join(self.skills_dir, f"{name}.py"), "w", encoding="utf-8") as fh:
            fh.write(code)

    def test_01_disk_sync_registers_pending_not_approved(self):
        """S1: skill có trên đĩa phải được đăng ký pending_review, KHÔNG phải approved."""
        self._write_skill_file("disk_skill_probe", BENIGN_SKILL)
        HunterAgent(self.db_path, skills_dir=self.skills_dir)

        row = self.storage.get_skill("disk_skill_probe")
        self.assertIsNotNone(row, "Skill trên đĩa phải được đồng bộ vào CSDL")
        self.assertEqual(row["approval_status"], "pending_review",
                         "TUYỆT ĐỐI không được tự phê duyệt skill từ đĩa")
        self.assertEqual(row["test_status"], "passed",
                         "Máy phải chạy kiểm tra tự động (test_status=passed)")
        # Chưa duyệt -> Hunter phải CHẶN
        hunter = HunterAgent(self.db_path, skills_dir=self.skills_dir)
        res = hunter.execute_skill("disk_skill_probe")
        self.assertEqual(res["status"], "blocked")
        self.assertIn("SECURITY GATE", res["message"])

    def test_02_approved_but_malicious_skill_is_still_blocked(self):
        """S3: phê duyệt không thay thế được kiểm tra chính sách — mã độc vẫn bị chặn."""
        self.storage.save_skill(
            run_id="unit_test", skill_name="approved_but_evil", domain="endpoint",
            description="Đã duyệt nhưng chứa mã nguy hiểm", skill_code=MALICIOUS_SKILL,
            target_threat="None")
        self.storage.update_skill_approval("approved_but_evil", "approved",
                                           "Lead SOC Analyst", "Duyệt thử nghiệm")
        hunter = HunterAgent(self.db_path, skills_dir=self.skills_dir)
        res = hunter.execute_skill("approved_but_evil")
        self.assertEqual(res["status"], "blocked")
        self.assertEqual(res["test_status"], "policy_violation")
        self.assertTrue(res.get("violations"), "Phải liệt kê được vi phạm AST")

    def test_03_regenerating_code_resets_approval(self):
        """S4: mã mới (cùng tên skill) phải mất phê duyệt cũ — chống 'rửa phê duyệt'."""
        self.storage.save_skill(run_id="r1", skill_name="evolving_skill", domain="web",
                                description="v1", skill_code=BENIGN_SKILL, target_threat="T1")
        self.storage.update_skill_approval("evolving_skill", "approved", "Analyst", "v1 ok")
        self.assertEqual(self.storage.get_skill("evolving_skill")["approval_status"], "approved")

        # Sinh lại mã với cùng tên -> phải quay về pending_review
        self.storage.save_skill(run_id="r2", skill_name="evolving_skill", domain="web",
                                description="v2", skill_code=MALICIOUS_SKILL, target_threat="T2")
        row = self.storage.get_skill("evolving_skill")
        self.assertEqual(row["approval_status"], "pending_review")
        self.assertEqual(row["test_status"], "pending")


class TestSkillGenerationGate(unittest.TestCase):
    """S5: generate_agent_skill phải từ chối mã độc TRƯỚC KHI ghi file."""

    PROD_DB = os.path.join(parent_dir, "cti_framework.db")
    SKILL_DIR = os.path.join(parent_dir, "skills", "generated")

    def tearDown(self):
        # Dọn sạch mọi vệt thử nghiệm để repo luôn sạch
        for fname in ("unit_test_malicious_probe.py", "unit_test_safe_probe.py"):
            path = os.path.join(self.SKILL_DIR, fname)
            if os.path.exists(path):
                os.remove(path)
        if os.path.exists(self.PROD_DB):
            import sqlite3
            conn = sqlite3.connect(self.PROD_DB)
            for name in ("unit_test_malicious_probe", "unit_test_safe_probe"):
                conn.execute("DELETE FROM agent_skills WHERE skill_name = ?", (name,))
                conn.execute("DELETE FROM skill_verification_runs WHERE skill_name = ?", (name,))
            conn.commit()
            conn.close()

    def test_malicious_skill_rejected_before_write(self):
        res = json.loads(generate_agent_skill(
            skill_name="unit_test_malicious_probe",
            domain="endpoint",
            description="Probe mã độc cho unit test",
            target_threat="None",
            python_code=MALICIOUS_SKILL,
        ))
        self.assertEqual(res["status"], "security_rejected")
        self.assertTrue(res["violations"])
        self.assertFalse(
            os.path.exists(os.path.join(self.SKILL_DIR, "unit_test_malicious_probe.py")),
            "Mã bị từ chối KHÔNG được ghi xuống đĩa")

        # CSDL phải ghi nhận phiên bị từ chối (audit trail)
        import sqlite3
        conn = sqlite3.connect(self.PROD_DB)
        row = conn.execute(
            "SELECT test_status, approval_status FROM skill_verification_runs "
            "WHERE skill_name = 'unit_test_malicious_probe' ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        self.assertIsNotNone(row, "Phải có bản ghi audit cho ca bị từ chối")
        self.assertEqual(row[0], "policy_violation")
        self.assertEqual(row[1], "rejected")

    def test_benign_skill_created_pending_review(self):
        res = json.loads(generate_agent_skill(
            skill_name="unit_test_safe_probe",
            domain="endpoint",
            description="Skill hợp lệ cho unit test",
            target_threat="None",
            python_code=BENIGN_SKILL,
        ))
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["approval_status"], "pending_review")
        self.assertEqual(res["test_status"], "passed")
        self.assertTrue(os.path.exists(os.path.join(self.SKILL_DIR, "unit_test_safe_probe.py")))


class TestAPIAccessGuard(unittest.TestCase):
    """S6: API local-only + chặn Origin từ trang web khác."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from web.app import app
        cls.client = TestClient(app)

    def test_local_request_allowed(self):
        res = self.client.get("/api/system/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "healthy")

    def test_non_local_host_rejected(self):
        res = self.client.get("/api/system/health", headers={"host": "evil.example.com"})
        self.assertEqual(res.status_code, 403)

    def test_foreign_origin_post_rejected(self):
        res = self.client.post("/api/hunter/execute",
                               json={"skill_name": "nope"},
                               headers={"origin": "http://evil.example.com"})
        self.assertEqual(res.status_code, 403)

    def test_local_origin_post_allowed(self):
        res = self.client.post("/api/hunter/execute",
                               json={"skill_name": "unit_test_not_exist"},
                               headers={"origin": "http://localhost:9090"})
        # Qua được cổng Origin (handler trả lỗi 'skill không tồn tại' chứ không phải 403)
        self.assertNotEqual(res.status_code, 403)
        self.assertEqual(res.json().get("status"), "error")


class TestStaleRunCleanup(unittest.TestCase):
    """S7: run bị kẹt 'running' phải được dọn khi khởi động."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_path = self.tmp.name
        self.tmp.close()
        self.storage = StorageManager(self.tmp_path)

    def tearDown(self):
        try:
            self.storage.conn.close()
        except Exception:
            pass
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)

    def test_fail_stale_runs(self):
        import sqlite3
        conn = sqlite3.connect(self.tmp_path)
        conn.execute(
            "INSERT INTO agent_runs (run_id, task, status, start_time, model_name) "
            "VALUES ('stale_run_1', 'task', 'running', '2026-01-01T00:00:00', 'qwen2.5:7b')")
        conn.commit()
        conn.close()

        cleaned = self.storage.fail_stale_runs()
        self.assertEqual(cleaned, 1)
        row = self.storage.get_agent_runs(status="failed")
        self.assertEqual(len(row), 1)
        self.assertEqual(row[0]["run_id"], "stale_run_1")
        # Chạy lần 2 không còn gì để dọn
        self.assertEqual(self.storage.fail_stale_runs(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
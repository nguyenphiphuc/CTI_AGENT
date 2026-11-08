"""
Comprehensive End-to-End Test Suite for xAI & Trust Verification Module.
Implements the 12 mandatory verification and gating scenarios:
1. Exact match IOC in source
2. Not found IOC (AI hallucination prevention)
3. RFC 5737 / RFC 1918 Example & testing IOCs
4. Mentioned but unconfirmed maliciousness (Benign public DNS)
5. Pure TTP / Narrative article without IOCs
6. Unreachable / HTTP error source document
7. Content hash drift verification
8. Unsupported MITRE ATT&CK / CVE claim
9. Skill without source report or evidence references
10. Skill syntax error and sandbox failure
11. Hunter Agent blocks unapproved skill execution
12. Wazuh sync gate blocks unverified/unapproved IOCs
"""

import os
import sys
import json
import sqlite3
import tempfile
import unittest

# Ensure cti_framework directory is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from validators.xai_verifier import (
    XAIVerifier,
    calculate_sha256,
    normalize_defanged,
    find_indicator_in_text,
    is_rfc_example_or_private_ip,
    assess_indicator_maliciousness,
    compute_multi_factor_trust_score
)
from storage.sqlite_manager import StorageManager
from core.hunter_agent import HunterAgent


class TestXAIVerifierE2E(unittest.TestCase):

    def setUp(self):
        # Create a fresh temporary database for each test run
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()
        self.storage = StorageManager(self.temp_db_path)
        self.verifier = XAIVerifier(self.storage)

    def tearDown(self):
        try:
            self.storage.conn.close()
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
        except Exception:
            pass

    # --- Scenario 1: IOC khớp chính xác trong bài (Exact Match) ---
    def test_01_exact_match_ioc(self):
        article_text = (
            "Security researchers detected malware payload dropping a backdoor on infected machines. "
            "The sample establishes an active connection to 45.33.32.156 which operates as a C2 command and control server."
        )
        res = self.verifier.verify_ioc("45.33.32.156", "ipv4", article_text)
        
        self.assertEqual(res["source_match_status"], "exact_match")
        self.assertEqual(res["maliciousness_status"], "maliciousness_confirmed")
        self.assertEqual(res["trust_status"], "verified")
        self.assertGreaterEqual(res["trust_score"], 0.8)
        self.assertEqual(res["evidence_quote"], "45.33.32.156")
        self.assertGreaterEqual(res["char_offset_start"], 0)

    # --- Scenario 2: IOC không xuất hiện trong bài (Not Found / Hallucination) ---
    def test_02_not_found_ioc(self):
        article_text = "The attackers used legitimate administrative tools and compromised credentials."
        res = self.verifier.verify_ioc("193.142.59.88", "ipv4", article_text)
        
        self.assertEqual(res["source_match_status"], "not_found")
        self.assertEqual(res["trust_status"], "rejected")
        self.assertEqual(res["trust_score"], 0.0)
        self.assertEqual(res["char_offset_start"], -1)
        self.assertEqual(res["evidence_quote"], "")

    # --- Scenario 3: IOC là địa chỉ ví dụ / thử nghiệm RFC 5737 / Private IP ---
    def test_03_example_or_testing_ioc(self):
        article_text = (
            "In this educational tutorial, for demonstration purposes we use the RFC 5737 sample IP 198.51.100.25 "
            "as a mock target, along with 1.2.3.4 and internal host 192.168.1.50."
        )
        # Check RFC 5737 testnet IP
        res_testnet = self.verifier.verify_ioc("198.51.100.25", "ipv4", article_text)
        self.assertEqual(res_testnet["source_match_status"], "exact_match")
        self.assertEqual(res_testnet["maliciousness_status"], "example_or_benign")
        self.assertEqual(res_testnet["trust_status"], "partially_verified")

        # Check placeholder IP 1.2.3.4
        res_placeholder = self.verifier.verify_ioc("1.2.3.4", "ipv4", article_text)
        self.assertEqual(res_placeholder["maliciousness_status"], "example_or_benign")

        # Check private RFC 1918 IP
        res_private = self.verifier.verify_ioc("192.168.1.50", "ipv4", article_text)
        self.assertEqual(res_private["maliciousness_status"], "example_or_benign")

    # --- Scenario 4: IOC có trong bài nhưng nguồn không khẳng định độc hại (Benign DNS) ---
    def test_04_mentioned_not_confirmed_ioc(self):
        article_text = (
            "The malicious script configures network settings to query Google Public DNS at 8.8.8.8 "
            "and Cloudflare DNS at 1.1.1.1 to verify external connectivity."
        )
        res = self.verifier.verify_ioc("8.8.8.8", "ipv4", article_text)
        
        self.assertEqual(res["source_match_status"], "exact_match")
        self.assertEqual(res["maliciousness_status"], "mentioned_not_confirmed")
        self.assertNotEqual(res["maliciousness_status"], "maliciousness_confirmed")
        self.assertEqual(res["trust_status"], "partially_verified")

    # --- Scenario 5: Bài báo thuần TTP / nhận định, không có IOC ---
    def test_05_ttp_only_article_no_iocs(self):
        article_text = (
            "APT29 threat actors leveraged spearphishing emails containing malicious PDF attachments. "
            "Upon opening, the document exploited a vulnerability in the viewer to execute PowerShell code "
            "and dump credentials from memory."
        )
        # Verify MITRE claim
        claim_res = self.verifier.verify_claim(
            claim="T1059: PowerShell execution",
            claim_type="mitre_attack",
            raw_content=article_text
        )
        self.assertEqual(claim_res["verification_status"], "verified")
        self.assertGreater(claim_res["trust_score"], 0.7)

        # Ensure no hallucinated IP passes verification
        res_phantom = self.verifier.verify_ioc("103.22.44.11", "ipv4", article_text)
        self.assertEqual(res_phantom["source_match_status"], "not_found")
        self.assertEqual(res_phantom["trust_status"], "rejected")

    # --- Scenario 6: Nguồn không truy cập được hoặc bị lỗi HTTP ---
    def test_06_unreachable_or_http_error_source(self):
        doc = self.verifier.verify_source_document(
            raw_content="",
            source_url="https://cisa.gov/advisory/404-broken",
            http_status=404,
            fetch_error="HTTP 404 Not Found"
        )
        self.assertEqual(doc["fetch_status"], "http_error")
        self.assertEqual(doc["content_hash"], "")
        self.assertEqual(doc["raw_content"], "")
        self.assertIn("404", doc["fetch_error"])

    # --- Scenario 7: Nội dung bài báo thay đổi (Content Hash Drift) ---
    def test_07_content_hash_drift(self):
        original_content = "C2 server reported at 104.244.42.1."
        doc_original = self.verifier.verify_source_document(
            raw_content=original_content,
            source_url="https://thehackernews.com/article-1"
        )
        original_hash = doc_original["content_hash"]
        self.assertTrue(len(original_hash) == 64)

        # Altered content
        tampered_content = "C2 server reported at 104.244.42.2."
        tampered_hash = calculate_sha256(tampered_content)

        self.assertNotEqual(original_hash, tampered_hash, "Tampered content must produce a distinct hash!")

    # --- Scenario 8: Nhận định ATT&CK / CVE không có bằng chứng hành vi ---
    def test_08_unsupported_attack_or_cve_claim(self):
        article_text = "The report discussed general cybersecurity trends and mentioned the word injection in passing."
        
        # Claim MITRE Process Injection T1055 without evidence
        claim_res = self.verifier.verify_claim(
            claim="T1055: Process Injection into svchost",
            claim_type="mitre_attack",
            raw_content=article_text
        )
        self.assertIn(claim_res["verification_status"], ("insufficient_evidence", "rejected"))
        self.assertLessEqual(claim_res["trust_score"], 0.3)

        # Claim CVE not in text
        cve_res = self.verifier.verify_claim(
            claim="CVE-2024-9999",
            claim_type="cve",
            raw_content=article_text
        )
        self.assertEqual(cve_res["verification_status"], "rejected")
        self.assertEqual(cve_res["trust_score"], 0.0)

    # --- Scenario 9: Skill không dẫn chiếu được báo cáo nguồn ---
    def test_09_skill_without_source_reports_or_evidence(self):
        skill_code = """
from skills.base_skill import BaseAgentSkill
class MySkill(BaseAgentSkill):
    def execute(self, params):
        return {'status': 'CLEAN'}
"""
        res = self.verifier.verify_skill(
            skill_name="test_skill",
            skill_code=skill_code,
            source_reports=[],  # Empty reports list
            evidence_refs=[]    # Empty evidence list
        )
        self.assertEqual(res["verification_status"], "unverified")
        self.assertEqual(res["approval_status"], "pending_review")

    # --- Scenario 10: Skill có lỗi cú pháp hoặc chạy thử thất bại ---
    def test_10_skill_syntax_error(self):
        broken_skill_code = """
def broken_func(
    print("Syntax error missing closing parenthesis"
"""
        res = self.verifier.verify_skill(
            skill_name="broken_skill",
            skill_code=broken_skill_code,
            source_reports=[1],
            evidence_refs=[10]
        )
        self.assertEqual(res["verification_status"], "rejected")
        self.assertEqual(res["test_status"], "syntax_error")
        self.assertEqual(res["approval_status"], "rejected")

    # --- Scenario 11: Cố tình kích hoạt Hunter Agent với skill chưa duyệt ---
    def test_11_hunter_agent_blocks_unapproved_skill(self):
        # Save a pending skill into database
        self.storage.save_skill(
            run_id="run_101",
            skill_name="unapproved_hunt_skill",
            domain="web",
            description="Experimental hunt skill",
            skill_code="""
from skills.base_skill import BaseAgentSkill
class UnapprovedSkill(BaseAgentSkill):
    def execute(self, params):
        return {'status': 'EXECUTED'}
"""
        )
        # Note: status is pending_review by default in sqlite_manager migrations
        hunter = HunterAgent(self.temp_db_path)
        
        # Execute skill that has approval_status == 'pending_review'
        exec_res = hunter.execute_skill("unapproved_hunt_skill")
        
        self.assertEqual(exec_res["status"], "blocked", "Hunter Agent must block unapproved skill!")
        self.assertIn("SECURITY GATE", exec_res["message"])
        self.assertEqual(exec_res["approval_status"], "pending_review")

        # Now approve skill and verify execution is unblocked
        self.storage.update_skill_approval("unapproved_hunt_skill", "approved", "Lead SOC Analyst", "Passed code audit")
        approved_res = hunter.execute_skill("unapproved_hunt_skill")
        self.assertEqual(approved_res["status"], "success", "Hunter Agent must allow approved skill to run!")

    # --- Scenario 12: Cố tình đẩy IOC chưa kiểm chứng sang Wazuh CDB List ---
    def test_12_wazuh_sync_blocks_unverified_iocs(self):
        # Save unverified raw IOC
        self.storage.save_ioc(
            run_id="run_raw",
            ioc_type="ipv4",
            ioc_value="1.2.3.4",
            status="observed",
            source_match_status="unverified",
            maliciousness_status="insufficient_evidence",
            trust_status="unverified",
            approval_status="pending_review"
        )
        # Save an RFC 5737 test IP
        self.storage.save_ioc(
            run_id="run_raw",
            ioc_type="ipv4",
            ioc_value="198.51.100.99",
            status="observed",
            source_match_status="exact_match",
            maliciousness_status="example_or_benign",
            trust_status="partially_verified",
            approval_status="pending_review"
        )
        # Save verified malicious IOC
        self.storage.save_ioc(
            run_id="run_good",
            ioc_type="ipv4",
            ioc_value="45.33.32.156",
            status="verified",
            source_match_status="exact_match",
            maliciousness_status="maliciousness_confirmed",
            trust_status="verified",
            approval_status="approved"
        )

        cursor = self.storage.conn.cursor()
        
        # Query matching the exact Wazuh sync security gate in app.py & cron_agent.py
        gated_query = """
            SELECT ioc_type, ioc_value, confidence, status, trust_score, trust_status, approval_status, maliciousness_status
            FROM extracted_iocs 
            WHERE is_expired = 0 
              AND (
                approval_status = 'approved'
                OR (trust_status = 'verified' AND maliciousness_status = 'maliciousness_confirmed' AND source_match_status IN ('exact_match', 'normalized_match'))
              )
        """
        vetted_iocs = [dict(r) for r in cursor.execute(gated_query).fetchall()]
        vetted_values = [it["ioc_value"] for it in vetted_iocs]

        # Assertions
        self.assertIn("45.33.32.156", vetted_values, "Vetted malicious IOC must be allowed into Wazuh sync.")
        self.assertNotIn("1.2.3.4", vetted_values, "Unverified raw IOC must be blocked from Wazuh sync!")
        self.assertNotIn("198.51.100.99", vetted_values, "Example / benign IP must be blocked from Wazuh sync!")
        self.assertEqual(len(vetted_values), 1, "Only strictly vetted IOCs should pass the Wazuh sync gate.")


if __name__ == "__main__":
    unittest.main()

"""
Autonomous Defender & Threat Hunter Agent (The 2nd Agent)
Con Agent thứ 2 trong hệ thống:
- Nhận và nạp các Kỹ năng (Skills) được sinh động bởi CTI Intelligence Agent.
- Thực thi hành động săn lùng (Hunting) và phòng thủ chủ động (Active Defense).
- Phục vụ riêng biệt cho Web Security (quét mã nguồn Web, Webshell, CVE) hoặc Network Security (kiểm toán kết nối mạng C2).
"""

import os
import sys
import json
import logging
import importlib.util
from datetime import datetime
from typing import Dict, List, Any, Optional

from storage.sqlite_manager import StorageManager
from skills.base_skill import BaseAgentSkill
from validators.skill_security import scan_skill_code

logger = logging.getLogger("cti.hunter")

class HunterAgent:
    def __init__(self, db_path: Optional[str] = None, skills_dir: Optional[str] = None):
        if not db_path:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cti_framework.db")
        self.db = StorageManager(db_path)
        # skills_dir có thể bị tách riêng (test / cách ly), mặc định vẫn là skills/generated của repo
        self.skills_dir = skills_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills", "generated")
        os.makedirs(self.skills_dir, exist_ok=True)
        self._sync_disk_skills_to_db()

    def _sync_disk_skills_to_db(self):
        """
        Đồng bộ file Skill có sẵn trên đĩa vào CSDL khi chuyển dự án sang máy mới.

        AN TOÀN: kỹ năng từ đĩa CHỈ ĐƯỢC ĐĂNG KÝ Ở TRẠNG THÁI pending_review.
        Máy tự kiểm tra cú pháp + AST policy để điền test_status, nhưng PHÊ DUYỆT
        luôn là quyết định của chuyên viên — không có đường tự duyệt ngầm.
        """
        if not os.path.exists(self.skills_dir):
            return
        for fname in os.listdir(self.skills_dir):
            if fname.endswith(".py") and not fname.startswith("__"):
                clean_name = fname[:-3]
                existing = self.db.get_skill(clean_name)
                if existing:
                    continue
                file_path = os.path.join(self.skills_dir, fname)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        code = f.read()
                except Exception as read_err:
                    logger.warning("Không đọc được skill '%s': %s", clean_name, read_err)
                    continue

                domain = "web" if "web" in clean_name else ( "network" if any(k in clean_name for k in ("socket", "c2", "network")) else "endpoint")

                # Kiểm tra tự động (machine verification) — KHÔNG phải phê duyệt
                import ast as _ast
                try:
                    _ast.parse(code)
                    policy = scan_skill_code(code)
                    test_status = "passed" if policy["passed"] else "policy_violation"
                    test_output = policy["summary"]
                except SyntaxError as syn_err:
                    test_status = "syntax_error"
                    test_output = f"SyntaxError at line {syn_err.lineno}: {syn_err.msg}"

                self.db.save_skill(
                    run_id="bundled_repo",
                    skill_name=clean_name,
                    domain=domain,
                    description=f"Kỹ năng phòng thủ tích hợp sẵn: {clean_name}",
                    skill_code=code,
                    target_threat="Pre-packaged Defense Skill"
                )
                self.db.save_skill_verification_run(
                    skill_name=clean_name,
                    skill_version="1.0.0",
                    source_reports="[]",
                    evidence_refs="[]",
                    verification_status="verified" if test_status == "passed" else "unverified",
                    test_status=test_status,
                    test_output=test_output,
                    approval_status="pending_review"
                )
                logger.info("Đăng ký skill '%s' từ đĩa ở trạng thái pending_review (test_status=%s)",
                            clean_name, test_status)

    def list_available_skills(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lấy danh sách các kỹ năng săn lùng hiện có trong kho."""
        return self.db.get_all_skills(domain=domain)

    def load_skill_instance(self, skill_name: str) -> Optional[BaseAgentSkill]:
        """Nạp động mã nguồn Python của Skill vào bộ nhớ và khởi tạo đối tượng."""
        clean_name = skill_name.replace(".py", "")
        file_path = os.path.join(self.skills_dir, f"{clean_name}.py")
        
        # Nếu chưa có file trên đĩa nhưng có trong DB, tự động xuất ra file
        if not os.path.exists(file_path):
            skill_info = self.db.get_skill(clean_name)
            if skill_info and skill_info.get("skill_code"):
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(skill_info["skill_code"])
            else:
                return None

        try:
            spec = importlib.util.spec_from_file_location(clean_name, file_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[clean_name] = module
            spec.loader.exec_module(module)

            # Tìm class kế thừa từ BaseAgentSkill
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseAgentSkill) and attr is not BaseAgentSkill:
                    try:
                        return attr()
                    except TypeError:
                        skill_info = self.db.get_skill(clean_name) or {}
                        return attr(
                            name=clean_name,
                            domain=skill_info.get("domain", "general"),
                            description=skill_info.get("description", "Hunter Skill"),
                            target_threat=skill_info.get("target_threat", "General Threat")
                        )
            return None
        except Exception as e:
            logger.warning("Nạp skill '%s' thất bại: %s", clean_name, e)
            return None

    def execute_skill(self, skill_name: str, target_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Chạy một Kỹ năng săn lùng cụ thể do CTI Agent tạo ra (Được bảo vệ bởi Security Gate)."""
        clean_name = skill_name.replace(".py", "")
        skill_info = self.db.get_skill(clean_name)
        now = datetime.now().isoformat()

        if not skill_info:
            return {"status": "error", "message": f"Không tìm thấy Skill '{clean_name}' trong CSDL."}

        # --- xAI SECURITY GATE 1: Chặn thực thi skill chưa được phê duyệt ---
        approval_status = skill_info.get("approval_status", "pending_review")
        test_status = skill_info.get("test_status", "pending")

        if approval_status != "approved":
            return {
                "status": "blocked",
                "skill_name": clean_name,
                "approval_status": approval_status,
                "test_status": test_status,
                "timestamp": now,
                "message": f"[SECURITY GATE] Skill '{clean_name}' bị CHẶN THỰC THI vì chưa được phê duyệt xAI (Trạng thái duyệt: {approval_status}, Kiểm thử: {test_status}). Vui lòng phê duyệt kỹ năng trên Dashboard trước khi kích hoạt Hunter Agent.",
                "action_result": {
                    "status": "BLOCKED",
                    "reason": f"Skill approval_status is '{approval_status}', not 'approved'."
                }
            }

        # --- xAI SECURITY GATE 2: Tái kiểm tra AST policy TRƯỚC KHI NẠP MÃ ---
        # (Phòng trường hợp file/DB bị thay đổi sau khi được phê duyệt)
        code_to_check = skill_info.get("skill_code") or ""
        if not str(code_to_check).strip():
            file_candidate = os.path.join(self.skills_dir, f"{clean_name}.py")
            if os.path.exists(file_candidate):
                try:
                    with open(file_candidate, "r", encoding="utf-8") as fc:
                        code_to_check = fc.read()
                except Exception as read_err:
                    logger.warning("Không đọc được '%s' để kiểm tra AST: %s", file_candidate, read_err)
        policy = scan_skill_code(code_to_check)
        if not policy["passed"]:
            logger.error("[SECURITY GATE] Skill '%s' vi phạm AST policy: %s", clean_name, policy["summary"])
            return {
                "status": "blocked",
                "skill_name": clean_name,
                "approval_status": approval_status,
                "test_status": "policy_violation",
                "timestamp": now,
                "message": f"[SECURITY GATE] Skill '{clean_name}' bị CHẶN vì vi phạm chính sách an toàn: {policy['summary']}",
                "violations": policy["violations"],
                "action_result": {"status": "BLOCKED", "reason": "AST policy violation"}
            }

        skill_instance = self.load_skill_instance(clean_name)

        if not skill_instance:
            # Không có class BaseAgentSkill hợp lệ -> KHÔNG báo thành công giả
            self.db.record_skill_execution(clean_name)
            logger.error("Skill '%s' không nạp được instance hợp lệ — từ chối báo thành công.", clean_name)
            return {
                "status": "error",
                "skill_name": clean_name,
                "domain": skill_info.get("domain", "general"),
                "timestamp": now,
                "message": f"Skill '{clean_name}' không định nghĩa lớp kế thừa BaseAgentSkill hợp lệ — KHÔNG thực thi gì cả."
            }

        try:
            res = skill_instance.execute(target_params or {})
            self.db.record_skill_execution(clean_name)
            return {
                "status": "success",
                "skill_name": skill_instance.name,
                "domain": skill_instance.domain,
                "threat_target": skill_instance.target_threat,
                "timestamp": now,
                "action_result": res
            }
        except Exception as e:
            logger.exception("Lỗi khi thực thi Skill '%s'", clean_name)
            return {"status": "error", "message": f"Lỗi khi thực thi Skill: {str(e)}"}

    def run_automated_hunt(self, domain: str = "web", target_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Tự động chạy toàn bộ kỹ năng ĐÃ ĐƯỢC DUYỆT theo lĩnh vực:
        - domain='web': Phục vụ Web Security (quét mã nguồn Web, kiểm tra backdoor webshell).
        - domain='network': Phục vụ Network Security (quét kết nối socket, kiểm tra kết nối C2 IP).
        """
        all_skills = self.list_available_skills(domain=domain)
        approved_skills = [sk for sk in all_skills if sk.get("approval_status") == "approved"]

        if not approved_skills:
            pending_count = len([sk for sk in all_skills if sk.get("approval_status") != "approved"])
            return {
                "status": "idle",
                "message": f"Không có Skill nào trong lĩnh vực [{domain.upper()}] đã được PHÊ DUYỆT (Approved). "
                           f"Hiện có {pending_count} kỹ năng đang ở trạng thái chờ duyệt (Pending Review) trên Dashboard.",
                "executed_skills": []
            }

        results = []
        t_path = target_path if target_path else "."
        for sk in approved_skills:
            sname = sk["skill_name"]
            res = self.execute_skill(sname, {"target_path": t_path})
            results.append(res)

        return {
            "status": "completed",
            "domain": domain,
            "total_skills_executed": len(results),
            "timestamp": datetime.now().isoformat(),
            "executed_skills": results
        }

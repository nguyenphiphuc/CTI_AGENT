import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

class StorageManager:
    def __init__(self, db_path: str = "cti_framework.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._init_db()
        self._migrate_db()
        
    def _init_db(self):
        cursor = self.conn.cursor()
        
        # 1. Agent Runs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_runs (
                run_id TEXT PRIMARY KEY,
                task TEXT,
                status TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                result TEXT,
                model_name TEXT DEFAULT 'qwen2.5:7b',
                total_steps INTEGER DEFAULT 0
            )
        """)
        
        # 2. Execution Traces (Raw engine steps)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS execution_traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                step INTEGER,
                action_type TEXT,
                content TEXT,
                timestamp TIMESTAMP
            )
        """)
        
        # 3. Operational Agent Events (Granular telemetry timeline)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                event_type TEXT,
                step INTEGER DEFAULT 0,
                tool_name TEXT DEFAULT '',
                status TEXT DEFAULT 'info',
                duration_ms INTEGER DEFAULT 0,
                summary TEXT DEFAULT '',
                input_summary TEXT DEFAULT '',
                output_summary TEXT DEFAULT '',
                error_code TEXT DEFAULT '',
                timestamp TIMESTAMP
            )
        """)
        
        # 4. CTI Reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cti_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                title TEXT,
                source_url TEXT,
                published_date TEXT,
                summary TEXT,
                raw_content TEXT,
                created_at TIMESTAMP
            )
        """)
        
        # 5. Extracted IOCs (With Data Lifecycle & TTL)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS extracted_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                ioc_type TEXT,
                ioc_value TEXT UNIQUE,
                timestamp TIMESTAMP,
                status TEXT DEFAULT 'observed',
                confidence TEXT DEFAULT 'medium',
                context TEXT,
                report_id INTEGER,
                ttl_days INTEGER DEFAULT 14,
                expires_at TIMESTAMP,
                is_expired INTEGER DEFAULT 0,
                source_type TEXT DEFAULT 'tactical'
            )
        """)
        
        # 6. MITRE ATT&CK Mappings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                report_id INTEGER,
                technique_id TEXT,
                technique_name TEXT,
                tactic TEXT,
                confidence TEXT DEFAULT 'candidate',
                evidence TEXT,
                status TEXT DEFAULT 'candidate',
                timestamp TIMESTAMP
            )
        """)
        
        # 7. Defense Rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS defense_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                report_id INTEGER,
                rule_type TEXT,
                rule_name TEXT,
                rule_content TEXT,
                description TEXT DEFAULT '',
                syntax_status TEXT DEFAULT 'validation_pending',
                validation_error TEXT DEFAULT '',
                approval_status TEXT DEFAULT 'awaiting_approval',
                approved_by TEXT DEFAULT '',
                approved_at TIMESTAMP,
                mitre_technique_id TEXT DEFAULT '',
                timestamp TIMESTAMP
            )
        """)

        # 8. Dynamic Agent Skills (Synthesized by CTI Agent for Hunter/Defender Agent)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_skills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                skill_name TEXT UNIQUE,
                domain TEXT DEFAULT 'general',
                description TEXT DEFAULT '',
                skill_code TEXT,
                target_threat TEXT DEFAULT '',
                created_at TIMESTAMP,
                execution_count INTEGER DEFAULT 0,
                last_executed TIMESTAMP,
                status TEXT DEFAULT 'ready'
            )
        """)

        # 9. xAI & Grounding Verifications (Explainable AI Engine Legacy Table)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS xai_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                report_id INTEGER,
                entity_type TEXT,
                entity_value TEXT,
                is_grounded INTEGER DEFAULT 1,
                trust_score REAL DEFAULT 1.0,
                exact_quote TEXT DEFAULT '',
                char_offset_start INTEGER DEFAULT -1,
                char_offset_end INTEGER DEFAULT -1,
                explanation TEXT DEFAULT '',
                created_at TIMESTAMP
            )
        """)

        # 10. Evidence Records (Ground-truth verbatim source citations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                evidence_type TEXT,
                entity_value TEXT,
                exact_quote TEXT,
                char_offset_start INTEGER DEFAULT -1,
                char_offset_end INTEGER DEFAULT -1,
                quote_hash TEXT DEFAULT '',
                context_window TEXT DEFAULT '',
                created_at TIMESTAMP,
                FOREIGN KEY(report_id) REFERENCES cti_reports(id)
            )
        """)

        # 11. IOC Verifications (Multi-tier status, maliciousness context, provenance)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER,
                report_id INTEGER,
                run_id TEXT DEFAULT '',
                indicator TEXT,
                indicator_type TEXT,
                source_url TEXT,
                evidence_quote TEXT DEFAULT '',
                evidence_location TEXT DEFAULT '',
                source_match_status TEXT DEFAULT 'unverified',
                context_assessment TEXT DEFAULT '',
                maliciousness_status TEXT DEFAULT 'insufficient_evidence',
                external_verification_status TEXT DEFAULT 'unverified',
                verification_notes TEXT DEFAULT '',
                trust_score REAL DEFAULT 0.0,
                trust_status TEXT DEFAULT 'unverified',
                approval_status TEXT DEFAULT 'pending_review',
                verified_at TIMESTAMP
            )
        """)

        # 12. Claim & TTP Verifications (ATT&CK, CVE, Actor, Malware grounding)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS claim_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                run_id TEXT DEFAULT '',
                claim TEXT,
                claim_type TEXT,
                source_url TEXT,
                evidence_quote TEXT DEFAULT '',
                evidence_location TEXT DEFAULT '',
                reasoning_summary TEXT DEFAULT '',
                verification_status TEXT DEFAULT 'unverified',
                uncertainties TEXT DEFAULT '',
                supporting_references TEXT DEFAULT '[]',
                trust_score REAL DEFAULT 0.0,
                created_at TIMESTAMP
            )
        """)

        # 13. Skill Verification Runs (Sandbox test results & Provenance linkage)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS skill_verification_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT,
                skill_version TEXT DEFAULT '1.0.0',
                source_reports TEXT DEFAULT '[]',
                evidence_refs TEXT DEFAULT '[]',
                verification_status TEXT DEFAULT 'unverified',
                test_status TEXT DEFAULT 'pending',
                test_output TEXT DEFAULT '',
                approval_status TEXT DEFAULT 'pending_review',
                created_at TIMESTAMP
            )
        """)

        # 14. Approval Records (Audit trail for human reviewer decisions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS approval_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT,
                entity_id INTEGER,
                reviewer TEXT DEFAULT 'SOC Analyst',
                decision TEXT,
                reason TEXT DEFAULT '',
                created_at TIMESTAMP
            )
        """)
        self.conn.commit()

    def _migrate_db(self):
        """Safely add new columns to pre-existing tables without data loss."""
        cursor = self.conn.cursor()
        
        def add_column_if_missing(table: str, col_name: str, col_type: str):
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [row["name"] for row in cursor.fetchall()]
            if col_name not in columns:
                try:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

        # agent_runs migrations
        add_column_if_missing("agent_runs", "model_name", "TEXT DEFAULT 'qwen2.5:7b'")
        add_column_if_missing("agent_runs", "total_steps", "INTEGER DEFAULT 0")
        add_column_if_missing("agent_runs", "cti_profile", "TEXT DEFAULT 'all'")
        add_column_if_missing("agent_runs", "artifact_focus", "TEXT DEFAULT 'all'")
        add_column_if_missing("agent_runs", "trust_score", "REAL DEFAULT 100.0")

        # extracted_iocs migrations (Data Lifecycle, TTL & xAI Grounding support)
        add_column_if_missing("extracted_iocs", "status", "TEXT DEFAULT 'observed'")
        add_column_if_missing("extracted_iocs", "confidence", "TEXT DEFAULT 'medium'")
        add_column_if_missing("extracted_iocs", "context", "TEXT")
        add_column_if_missing("extracted_iocs", "report_id", "INTEGER")
        add_column_if_missing("extracted_iocs", "ttl_days", "INTEGER DEFAULT 14")
        add_column_if_missing("extracted_iocs", "expires_at", "TIMESTAMP")
        add_column_if_missing("extracted_iocs", "is_expired", "INTEGER DEFAULT 0")
        add_column_if_missing("extracted_iocs", "source_type", "TEXT DEFAULT 'tactical'")
        add_column_if_missing("extracted_iocs", "trust_score", "REAL DEFAULT 100.0")
        add_column_if_missing("extracted_iocs", "grounding_status", "TEXT DEFAULT 'grounded'")
        add_column_if_missing("extracted_iocs", "exact_quote", "TEXT DEFAULT ''")
        add_column_if_missing("extracted_iocs", "char_offset_start", "INTEGER DEFAULT -1")
        add_column_if_missing("extracted_iocs", "char_offset_end", "INTEGER DEFAULT -1")

        # Backfill legacy expires_at if missing
        try:
            cursor.execute("""
                UPDATE extracted_iocs 
                SET ttl_days = CASE 
                    WHEN ioc_type = 'ipv4' THEN 14
                    WHEN ioc_type = 'domain' THEN 30
                    WHEN ioc_type IN ('sha256', 'md5') THEN 90
                    WHEN ioc_type = 'cve' THEN 730
                    ELSE 14 END,
                    expires_at = datetime(coalesce(timestamp, CURRENT_TIMESTAMP), '+' || (CASE 
                        WHEN ioc_type = 'ipv4' THEN 14
                        WHEN ioc_type = 'domain' THEN 30
                        WHEN ioc_type IN ('sha256', 'md5') THEN 90
                        WHEN ioc_type = 'cve' THEN 730
                        ELSE 14 END) || ' days')
                WHERE expires_at IS NULL
            """)
            self.conn.commit()
        except Exception:
            pass

        # defense_rules migrations
        add_column_if_missing("defense_rules", "report_id", "INTEGER")
        add_column_if_missing("defense_rules", "description", "TEXT DEFAULT ''")
        add_column_if_missing("defense_rules", "syntax_status", "TEXT DEFAULT 'validation_pending'")
        add_column_if_missing("defense_rules", "validation_error", "TEXT DEFAULT ''")
        add_column_if_missing("defense_rules", "approval_status", "TEXT DEFAULT 'awaiting_approval'")
        add_column_if_missing("defense_rules", "approved_by", "TEXT DEFAULT ''")
        add_column_if_missing("defense_rules", "approved_at", "TIMESTAMP")
        add_column_if_missing("defense_rules", "mitre_technique_id", "TEXT DEFAULT ''")

        # cti_reports migrations (Provenance & Fetch audit)
        add_column_if_missing("cti_reports", "content_hash", "TEXT DEFAULT ''")
        add_column_if_missing("cti_reports", "source_publisher", "TEXT DEFAULT ''")
        add_column_if_missing("cti_reports", "http_status", "INTEGER DEFAULT 200")
        add_column_if_missing("cti_reports", "fetched_at", "TEXT DEFAULT ''")
        add_column_if_missing("cti_reports", "fetch_status", "TEXT DEFAULT 'success'")
        add_column_if_missing("cti_reports", "fetch_error", "TEXT DEFAULT ''")

        # extracted_iocs migrations (xAI Provenance & Multi-tier Trust)
        add_column_if_missing("extracted_iocs", "source_match_status", "TEXT DEFAULT 'unverified'")
        add_column_if_missing("extracted_iocs", "context_assessment", "TEXT DEFAULT ''")
        add_column_if_missing("extracted_iocs", "maliciousness_status", "TEXT DEFAULT 'insufficient_evidence'")
        add_column_if_missing("extracted_iocs", "external_verification_status", "TEXT DEFAULT 'unverified'")
        add_column_if_missing("extracted_iocs", "verification_notes", "TEXT DEFAULT ''")
        add_column_if_missing("extracted_iocs", "trust_status", "TEXT DEFAULT 'unverified'")
        add_column_if_missing("extracted_iocs", "approval_status", "TEXT DEFAULT 'pending_review'")

        # agent_skills migrations (Skill lifecycle, provenance & sandbox status)
        add_column_if_missing("agent_skills", "skill_version", "TEXT DEFAULT '1.0.0'")
        add_column_if_missing("agent_skills", "source_reports", "TEXT DEFAULT '[]'")
        add_column_if_missing("agent_skills", "evidence_refs", "TEXT DEFAULT '[]'")
        add_column_if_missing("agent_skills", "verification_status", "TEXT DEFAULT 'unverified'")
        add_column_if_missing("agent_skills", "test_status", "TEXT DEFAULT 'pending'")
        add_column_if_missing("agent_skills", "approval_status", "TEXT DEFAULT 'pending_review'")

        self.conn.commit()

    # --- Agent Run Operations ---
    def start_run(self, run_id: str, task: str, model_name: str = "qwen2.5:7b"):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            """INSERT INTO agent_runs (run_id, task, status, start_time, model_name, total_steps) 
               VALUES (?, ?, ?, ?, ?, 0)
               ON CONFLICT(run_id) DO UPDATE SET status = 'running', start_time = excluded.start_time""",
            (run_id, task, "running", now, model_name)
        )
        self.conn.commit()

    def finish_run(self, run_id: str, status: str, result: str, total_steps: int = 0):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            "UPDATE agent_runs SET status = ?, end_time = ?, result = ?, total_steps = ? WHERE run_id = ?",
            (status, now, result, total_steps, run_id)
        )
        self.conn.commit()

    def get_agent_runs(self, status: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        if status and status != "all":
            cursor.execute(
                "SELECT * FROM agent_runs WHERE status = ? ORDER BY start_time DESC LIMIT ? OFFSET ?",
                (status, limit, offset)
            )
        else:
            cursor.execute(
                "SELECT * FROM agent_runs ORDER BY start_time DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_agent_run_detail(self, run_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM agent_runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        
        # Attach events
        cursor.execute("SELECT * FROM agent_events WHERE run_id = ? ORDER BY event_id ASC", (run_id,))
        data["events"] = [dict(r) for r in cursor.fetchall()]
        
        # Attach raw traces
        cursor.execute("SELECT * FROM execution_traces WHERE run_id = ? ORDER BY step ASC, id ASC", (run_id,))
        data["traces"] = [dict(r) for r in cursor.fetchall()]
        
        # Attach associated IOCs
        cursor.execute("SELECT * FROM extracted_iocs WHERE run_id = ?", (run_id,))
        data["iocs"] = [dict(r) for r in cursor.fetchall()]
        
        # Attach associated Rules
        cursor.execute("SELECT * FROM defense_rules WHERE run_id = ?", (run_id,))
        data["rules"] = [dict(r) for r in cursor.fetchall()]

        # Attach associated MITRE
        cursor.execute("SELECT * FROM mitre_mappings WHERE run_id = ?", (run_id,))
        data["mitre"] = [dict(r) for r in cursor.fetchall()]

        return data

    # --- Telemetry & Traces Operations ---
    def log_trace(self, run_id: str, step: int, action_type: str, content: Any):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO execution_traces (run_id, step, action_type, content, timestamp) VALUES (?, ?, ?, ?, ?)",
            (run_id, step, action_type, json.dumps(content, ensure_ascii=False) if not isinstance(content, str) else content, datetime.now().isoformat())
        )
        self.conn.commit()

    def log_event(self, run_id: str, event_type: str, step: int = 0, tool_name: str = "",
                  status: str = "info", duration_ms: int = 0, summary: str = "",
                  input_summary: str = "", output_summary: str = "", error_code: str = "") -> Dict[str, Any]:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            """INSERT INTO agent_events 
               (run_id, event_type, step, tool_name, status, duration_ms, summary, input_summary, output_summary, error_code, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, event_type, step, tool_name, status, duration_ms, summary, input_summary, output_summary, error_code, now)
        )
        self.conn.commit()
        return {
            "event_id": cursor.lastrowid,
            "run_id": run_id,
            "event_type": event_type,
            "step": step,
            "tool_name": tool_name,
            "status": status,
            "duration_ms": duration_ms,
            "summary": summary,
            "input_summary": input_summary,
            "output_summary": output_summary,
            "error_code": error_code,
            "timestamp": now
        }

    def get_events(self, run_id: Optional[str] = None, event_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM agent_events"
        params = []
        conditions = []
        if run_id:
            conditions.append("run_id = ?")
            params.append(run_id)
        if event_type and event_type != "all":
            conditions.append("event_type = ?")
            params.append(event_type)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY event_id DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    # --- CTI Reports Operations ---
    def save_cti_report(self, run_id: str, title: str, source_url: str, published_date: str,
                        summary: str, raw_content: str = "", content_hash: str = "",
                        source_publisher: str = "", http_status: int = 200,
                        fetched_at: str = "", fetch_status: str = "success",
                        fetch_error: str = "") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        if not fetched_at:
            fetched_at = now
        cursor.execute(
            """INSERT INTO cti_reports (run_id, title, source_url, published_date, summary, raw_content,
                                        content_hash, source_publisher, http_status, fetched_at, fetch_status, fetch_error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, title, source_url, published_date, summary, raw_content,
             content_hash, source_publisher, http_status, fetched_at, fetch_status, fetch_error, now)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_cti_reports(self, search: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        if search:
            cursor.execute(
                """SELECT r.*, 
                          (SELECT COUNT(*) FROM extracted_iocs WHERE run_id = r.run_id) as ioc_count,
                          (SELECT COUNT(*) FROM mitre_mappings WHERE run_id = r.run_id) as mitre_count,
                          (SELECT COUNT(*) FROM defense_rules WHERE run_id = r.run_id) as rule_count
                   FROM cti_reports r 
                   WHERE r.title LIKE ? OR r.summary LIKE ? OR r.source_url LIKE ?
                   ORDER BY r.created_at DESC LIMIT ? OFFSET ?""",
                (f"%{search}%", f"%{search}%", f"%{search}%", limit, offset)
            )
        else:
            cursor.execute(
                """SELECT r.*, 
                          (SELECT COUNT(*) FROM extracted_iocs WHERE run_id = r.run_id) as ioc_count,
                          (SELECT COUNT(*) FROM mitre_mappings WHERE run_id = r.run_id) as mitre_count,
                          (SELECT COUNT(*) FROM defense_rules WHERE run_id = r.run_id) as rule_count
                   FROM cti_reports r 
                   ORDER BY r.created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset)
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_cti_report_detail(self, report_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cti_reports WHERE id = ?", (report_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        run_id = data["run_id"]
        
        # Link to IOCs, MITRE, Rules, Events
        cursor.execute("SELECT * FROM extracted_iocs WHERE run_id = ?", (run_id,))
        data["iocs"] = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM mitre_mappings WHERE run_id = ?", (run_id,))
        data["mitre"] = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM defense_rules WHERE run_id = ?", (run_id,))
        data["rules"] = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM agent_runs WHERE run_id = ?", (run_id,))
        agent_run = cursor.fetchone()
        data["agent_run"] = dict(agent_run) if agent_run else None

        # Link to Evidence Records
        cursor.execute("SELECT * FROM evidence_records WHERE report_id = ? ORDER BY id ASC", (report_id,))
        data["evidence_records"] = [dict(r) for r in cursor.fetchall()]

        # Link to IOC Verifications
        cursor.execute("SELECT * FROM ioc_verifications WHERE report_id = ? OR run_id = ? ORDER BY id ASC", (report_id, run_id))
        data["ioc_verifications"] = [dict(r) for r in cursor.fetchall()]

        # Link to Claim Verifications
        cursor.execute("SELECT * FROM claim_verifications WHERE report_id = ? OR run_id = ? ORDER BY id ASC", (report_id, run_id))
        data["claim_verifications"] = [dict(r) for r in cursor.fetchall()]

        return data

    # --- IOC Operations (Data Lifecycle & Expiration) ---
    def save_ioc(self, run_id: str, ioc_type: str, ioc_value: str, status: str = "observed",
                 confidence: str = "medium", context: str = "", report_id: Optional[int] = None,
                 ttl_days: Optional[int] = None, source_type: str = "tactical",
                 source_match_status: str = "unverified", context_assessment: str = "",
                 maliciousness_status: str = "insufficient_evidence", external_verification_status: str = "unverified",
                 verification_notes: str = "", trust_score: float = 0.0, trust_status: str = "unverified",
                 approval_status: str = "pending_review", exact_quote: str = "",
                 char_offset_start: int = -1, char_offset_end: int = -1):
        cursor = self.conn.cursor()
        now_dt = datetime.now()
        now = now_dt.isoformat()
        
        # Calculate dynamic TTL per CTI tier if not explicitly specified
        if ttl_days is None:
            itype = str(ioc_type).lower()
            if itype == "ipv4":
                ttl_days = 14     # Tactical IP: 14 days
            elif itype == "domain":
                ttl_days = 30     # C2 Domain: 30 days
            elif itype in ("sha256", "md5"):
                ttl_days = 90     # File Hash: 90 days
            elif itype == "cve":
                ttl_days = 730    # CVE: 2 years (long-term strategic)
            else:
                ttl_days = 14
                
        expires_at = (now_dt + timedelta(days=ttl_days)).isoformat()
        
        try:
            cursor.execute(
                """INSERT INTO extracted_iocs 
                   (run_id, ioc_type, ioc_value, timestamp, status, confidence, context, report_id, ttl_days, expires_at, is_expired, source_type,
                    source_match_status, context_assessment, maliciousness_status, external_verification_status, verification_notes,
                    trust_score, trust_status, approval_status, exact_quote, char_offset_start, char_offset_end)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ioc_value) DO UPDATE SET 
                     status = excluded.status, 
                     context = coalesce(excluded.context, extracted_iocs.context),
                     confidence = excluded.confidence,
                     timestamp = excluded.timestamp,
                     ttl_days = excluded.ttl_days,
                     expires_at = excluded.expires_at,
                     is_expired = 0,
                     source_type = excluded.source_type,
                     source_match_status = excluded.source_match_status,
                     context_assessment = excluded.context_assessment,
                     maliciousness_status = excluded.maliciousness_status,
                     external_verification_status = excluded.external_verification_status,
                     verification_notes = excluded.verification_notes,
                     trust_score = excluded.trust_score,
                     trust_status = excluded.trust_status,
                     approval_status = excluded.approval_status,
                     exact_quote = excluded.exact_quote,
                     char_offset_start = excluded.char_offset_start,
                     char_offset_end = excluded.char_offset_end""",
                (run_id, ioc_type, ioc_value, now, status, confidence, context, report_id, ttl_days, expires_at, source_type,
                 source_match_status, context_assessment, maliciousness_status, external_verification_status, verification_notes,
                 trust_score, trust_status, approval_status, exact_quote, char_offset_start, char_offset_end)
            )
            self.conn.commit()
        except Exception:
            pass

    def check_and_expire_iocs(self) -> int:
        """Mark outdated IoCs as expired according to their dynamic TTL."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            """UPDATE extracted_iocs 
               SET is_expired = 1, status = 'expired'
               WHERE expires_at IS NOT NULL AND expires_at < ? AND is_expired = 0""",
            (now,)
        )
        self.conn.commit()
        return cursor.rowcount

    def get_iocs(self, ioc_type: Optional[str] = None, status: Optional[str] = None,
                 search: Optional[str] = None, is_expired: Optional[int] = None,
                 limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM extracted_iocs"
        params = []
        conditions = []
        if ioc_type and ioc_type != "all":
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
        if status and status != "all":
            conditions.append("status = ?")
            params.append(status)
        if is_expired is not None:
            conditions.append("is_expired = ?")
            params.append(is_expired)
        if search:
            conditions.append("(ioc_value LIKE ? OR context LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def update_ioc_status(self, ioc_id: int, status: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("UPDATE extracted_iocs SET status = ? WHERE id = ?", (status, ioc_id))
        self.conn.commit()
        return cursor.rowcount > 0

    # --- MITRE ATT&CK Operations ---
    def save_mitre_mapping(self, run_id: str, technique_id: str, technique_name: str,
                           tactic: str, confidence: str = "candidate", evidence: str = "",
                           status: str = "candidate", report_id: Optional[int] = None) -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            """INSERT INTO mitre_mappings (run_id, report_id, technique_id, technique_name, tactic, confidence, evidence, status, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, report_id, technique_id, technique_name, tactic, confidence, evidence, status, now)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_mitre_mappings(self, tactic: Optional[str] = None, search: Optional[str] = None,
                           limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM mitre_mappings"
        params = []
        conditions = []
        if tactic and tactic != "all":
            conditions.append("tactic = ?")
            params.append(tactic)
        if search:
            conditions.append("(technique_id LIKE ? OR technique_name LIKE ? OR evidence LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    # --- Defense Rules Operations ---
    def save_rule(self, run_id: str, rule_type: str, rule_name: str, rule_content: str,
                  description: str = "", syntax_status: str = "validation_pending",
                  validation_error: str = "", approval_status: str = "awaiting_approval",
                  mitre_technique_id: str = "", report_id: Optional[int] = None) -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            """INSERT INTO defense_rules 
               (run_id, report_id, rule_type, rule_name, rule_content, description, 
                syntax_status, validation_error, approval_status, mitre_technique_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, report_id, rule_type, rule_name, rule_content, description,
             syntax_status, validation_error, approval_status, mitre_technique_id, now)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_defense_rules(self, rule_type: Optional[str] = None, syntax_status: Optional[str] = None,
                          approval_status: Optional[str] = None, search: Optional[str] = None,
                          limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM defense_rules"
        params = []
        conditions = []
        if rule_type and rule_type != "all":
            conditions.append("rule_type = ?")
            params.append(rule_type)
        if syntax_status and syntax_status != "all":
            conditions.append("syntax_status = ?")
            params.append(syntax_status)
        if approval_status and approval_status != "all":
            conditions.append("approval_status = ?")
            params.append(approval_status)
        if search:
            conditions.append("(rule_name LIKE ? OR rule_content LIKE ? OR description LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def update_rule_validation(self, rule_id: int, syntax_status: str, validation_error: str = ""):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE defense_rules SET syntax_status = ?, validation_error = ? WHERE id = ?",
            (syntax_status, validation_error, rule_id)
        )
        self.conn.commit()

    def update_rule_approval(self, rule_id: int, approval_status: str, approved_by: str = "SOC Analyst"):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            "UPDATE defense_rules SET approval_status = ?, approved_by = ?, approved_at = ? WHERE id = ?",
            (approval_status, approved_by, now, rule_id)
        )
        self.conn.commit()

    def get_rule_by_id(self, rule_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM defense_rules WHERE id = ?", (rule_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    # --- Dashboard Overview Aggregations ---
    def get_dashboard_overview(self) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        
        # Reports count
        cursor.execute("SELECT count(*) as count FROM cti_reports")
        total_reports = cursor.fetchone()["count"]
        
        # IOCs counts & Expiration breakdown
        cursor.execute("SELECT count(*) as count FROM extracted_iocs")
        total_iocs = cursor.fetchone()["count"]
        cursor.execute("SELECT count(*) as count FROM extracted_iocs WHERE is_expired = 0")
        active_iocs = cursor.fetchone()["count"]
        cursor.execute("SELECT count(*) as count FROM extracted_iocs WHERE is_expired = 1")
        expired_iocs = cursor.fetchone()["count"]
        cursor.execute("SELECT ioc_type, count(*) as count FROM extracted_iocs GROUP BY ioc_type")
        ioc_types = {row["ioc_type"]: row["count"] for row in cursor.fetchall()}
        
        # Runs count & statuses
        cursor.execute("SELECT count(*) as count FROM agent_runs")
        total_runs = cursor.fetchone()["count"]
        cursor.execute("SELECT status, count(*) as count FROM agent_runs GROUP BY status")
        runs_status = {row["status"]: row["count"] for row in cursor.fetchall()}
        
        # MITRE count & tactic distribution
        cursor.execute("SELECT count(*) as count FROM mitre_mappings")
        total_mitre = cursor.fetchone()["count"]
        cursor.execute("SELECT tactic, count(*) as count FROM mitre_mappings WHERE tactic IS NOT NULL AND tactic != '' GROUP BY tactic")
        mitre_tactics = {row["tactic"]: row["count"] for row in cursor.fetchall()}
        
        # Rules counts
        cursor.execute("SELECT count(*) as count FROM defense_rules")
        total_rules = cursor.fetchone()["count"]
        cursor.execute("SELECT count(*) as count FROM defense_rules WHERE syntax_status = 'valid'")
        validated_rules = cursor.fetchone()["count"]
        cursor.execute("SELECT count(*) as count FROM defense_rules WHERE approval_status = 'awaiting_approval'")
        awaiting_rules = cursor.fetchone()["count"]
        cursor.execute("SELECT count(*) as count FROM defense_rules WHERE approval_status = 'approved'")
        approved_rules = cursor.fetchone()["count"]
        cursor.execute("SELECT rule_type, count(*) as count FROM defense_rules GROUP BY rule_type")
        rules_by_type = {row["rule_type"]: row["count"] for row in cursor.fetchall()}

        # Recent activities (last 10 events)
        cursor.execute("SELECT * FROM agent_events ORDER BY event_id DESC LIMIT 10")
        recent_events = [dict(r) for r in cursor.fetchall()]

        # Recent CTI reports (last 5)
        cursor.execute("SELECT id, run_id, title, source_url, published_date, created_at FROM cti_reports ORDER BY created_at DESC LIMIT 5")
        recent_reports = [dict(r) for r in cursor.fetchall()]

        # Recent Agent runs (last 5)
        cursor.execute("SELECT run_id, task, status, start_time, end_time, model_name, total_steps FROM agent_runs ORDER BY start_time DESC LIMIT 5")
        recent_runs = [dict(r) for r in cursor.fetchall()]

        # Runs by date (for timeline chart - last 7 days)
        cursor.execute("""
            SELECT substr(start_time, 1, 10) as date, count(*) as count 
            FROM agent_runs 
            GROUP BY date 
            ORDER BY date DESC LIMIT 10
        """)
        timeline_data = [dict(r) for r in cursor.fetchall()]
        timeline_data.reverse()

        return {
            "kpis": {
                "total_reports": total_reports,
                "total_iocs": total_iocs,
                "active_iocs": active_iocs,
                "expired_iocs": expired_iocs,
                "total_runs": total_runs,
                "running_tasks": runs_status.get("running", 0),
                "completed_tasks": runs_status.get("success", 0) + runs_status.get("completed", 0),
                "failed_tasks": runs_status.get("failed", 0),
                "total_mitre": total_mitre,
                "total_rules": total_rules,
                "validated_rules": validated_rules,
                "awaiting_approval_rules": awaiting_rules,
                "approved_rules": approved_rules,
            },
            "distributions": {
                "ioc_types": ioc_types,
                "runs_status": runs_status,
                "mitre_tactics": mitre_tactics,
                "rules_by_type": rules_by_type
            },
            "timeline": timeline_data,
            "recent_events": recent_events,
            "recent_reports": recent_reports,
            "recent_runs": recent_runs
        }

    # --- Tool Execution Metrics ---
    def get_tool_metrics(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                tool_name,
                COUNT(*) as total_calls,
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_calls,
                SUM(CASE WHEN status = 'failed' OR status = 'error' THEN 1 ELSE 0 END) as failed_calls,
                AVG(CASE WHEN duration_ms > 0 THEN duration_ms ELSE NULL END) as avg_duration_ms,
                MAX(timestamp) as last_called
            FROM agent_events
            WHERE tool_name IS NOT NULL AND tool_name != ''
            GROUP BY tool_name
        """)
        return [dict(r) for r in cursor.fetchall()]

    # --- Agent Generated Skills Operations (Pillar 3) ---
    def save_skill(self, run_id: str, skill_name: str, domain: str, description: str,
                   skill_code: str, target_threat: str = "") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO agent_skills (run_id, skill_name, domain, description, skill_code, target_threat, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ready')
            ON CONFLICT(skill_name) DO UPDATE SET
                skill_code = excluded.skill_code,
                description = excluded.description,
                target_threat = excluded.target_threat,
                domain = excluded.domain,
                -- MÃ MỚI = PHÊ DUYỆT MỚI: không kế thừa phê duyệt của phiên bản cũ
                approval_status = 'pending_review',
                test_status = 'pending',
                verification_status = 'unverified'
        """, (run_id, skill_name, domain, description, skill_code, target_threat, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_all_skills(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        if domain and domain.lower() != "all":
            cursor.execute("SELECT * FROM agent_skills WHERE domain = ? ORDER BY id DESC", (domain.lower(),))
        else:
            cursor.execute("SELECT * FROM agent_skills ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]

    def get_skill(self, skill_name: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM agent_skills WHERE skill_name = ?", (skill_name,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def record_skill_execution(self, skill_name: str):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            UPDATE agent_skills 
            SET execution_count = execution_count + 1, last_executed = ?, status = 'ready'
            WHERE skill_name = ?
        """, (now, skill_name))
        self.conn.commit()

    # --- xAI & Grounding Verifications (Pillar 2) ---
    def save_xai_verification(self, run_id: str, report_id: Optional[int], entity_type: str,
                              entity_value: str, is_grounded: bool, trust_score: float,
                              exact_quote: str = "", start_idx: int = -1, end_idx: int = -1,
                              explanation: str = "") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO xai_verifications (
                run_id, report_id, entity_type, entity_value, is_grounded, trust_score,
                exact_quote, char_offset_start, char_offset_end, explanation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, report_id, entity_type, entity_value, 1 if is_grounded else 0, trust_score,
              exact_quote, start_idx, end_idx, explanation, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_xai_verifications(self, run_id: str) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM xai_verifications WHERE run_id = ? ORDER BY id ASC", (run_id,))
        return [dict(r) for r in cursor.fetchall()]

    def update_run_xai_trust(self, run_id: str, trust_score: float, cti_profile: str = "all", artifact_focus: str = "all"):
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE agent_runs 
            SET trust_score = ?, cti_profile = ?, artifact_focus = ?
            WHERE run_id = ?
        """, (trust_score, cti_profile, artifact_focus, run_id))
        self.conn.commit()

    # --- Evidence Records Operations (Phase 2 & 3 xAI) ---
    def save_evidence_record(self, report_id: Optional[int], evidence_type: str, entity_value: str,
                             exact_quote: str, char_offset_start: int = -1, char_offset_end: int = -1,
                             quote_hash: str = "", context_window: str = "") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO evidence_records (
                report_id, evidence_type, entity_value, exact_quote,
                char_offset_start, char_offset_end, quote_hash, context_window, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (report_id, evidence_type, entity_value, exact_quote,
              char_offset_start, char_offset_end, quote_hash, context_window, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_evidence_records(self, report_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM evidence_records WHERE report_id = ? ORDER BY id ASC", (report_id,))
        return [dict(r) for r in cursor.fetchall()]

    # --- IOC Verifications Operations ---
    def save_ioc_verification(self, ioc_id: Optional[int], report_id: Optional[int], run_id: str,
                              indicator: str, indicator_type: str, source_url: str,
                              evidence_quote: str = "", evidence_location: str = "",
                              source_match_status: str = "unverified", context_assessment: str = "",
                              maliciousness_status: str = "insufficient_evidence",
                              external_verification_status: str = "unverified",
                              verification_notes: str = "", trust_score: float = 0.0,
                              trust_status: str = "unverified", approval_status: str = "pending_review") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO ioc_verifications (
                ioc_id, report_id, run_id, indicator, indicator_type, source_url,
                evidence_quote, evidence_location, source_match_status, context_assessment,
                maliciousness_status, external_verification_status, verification_notes,
                trust_score, trust_status, approval_status, verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ioc_id, report_id, run_id, indicator, indicator_type, source_url,
              evidence_quote, evidence_location, source_match_status, context_assessment,
              maliciousness_status, external_verification_status, verification_notes,
              trust_score, trust_status, approval_status, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_ioc_verifications(self, report_id: Optional[int] = None, run_id: Optional[str] = None,
                              trust_status: Optional[str] = None, approval_status: Optional[str] = None,
                              limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM ioc_verifications WHERE 1=1"
        params: List[Any] = []
        if report_id is not None:
            query += " AND report_id = ?"
            params.append(report_id)
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        if trust_status and trust_status.lower() != "all":
            query += " AND trust_status = ?"
            params.append(trust_status)
        if approval_status and approval_status.lower() != "all":
            query += " AND approval_status = ?"
            params.append(approval_status)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    def update_ioc_verification_approval(self, verification_id: int, approval_status: str,
                                         reviewer: str = "SOC Analyst", reason: str = "") -> bool:
        cursor = self.conn.cursor()
        cursor.execute("UPDATE ioc_verifications SET approval_status = ? WHERE id = ?", (approval_status, verification_id))
        
        # Also update corresponding extracted_iocs record if linked
        cursor.execute("SELECT indicator FROM ioc_verifications WHERE id = ?", (verification_id,))
        row = cursor.fetchone()
        if row and row["indicator"]:
            cursor.execute("UPDATE extracted_iocs SET approval_status = ? WHERE ioc_value = ?", (approval_status, row["indicator"]))
            
        self.save_approval_record("ioc", verification_id, reviewer, approval_status, reason)
        self.conn.commit()
        return True

    # --- Claim Verifications Operations ---
    def save_claim_verification(self, report_id: Optional[int], run_id: str, claim: str,
                                claim_type: str, source_url: str, evidence_quote: str = "",
                                evidence_location: str = "", reasoning_summary: str = "",
                                verification_status: str = "unverified", uncertainties: str = "",
                                supporting_references: str = "[]", trust_score: float = 0.0) -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO claim_verifications (
                report_id, run_id, claim, claim_type, source_url,
                evidence_quote, evidence_location, reasoning_summary,
                verification_status, uncertainties, supporting_references, trust_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (report_id, run_id, claim, claim_type, source_url,
              evidence_quote, evidence_location, reasoning_summary,
              verification_status, uncertainties, supporting_references, trust_score, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_claim_verifications(self, report_id: Optional[int] = None, run_id: Optional[str] = None,
                                claim_type: Optional[str] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM claim_verifications WHERE 1=1"
        params: List[Any] = []
        if report_id is not None:
            query += " AND report_id = ?"
            params.append(report_id)
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        if claim_type and claim_type.lower() != "all":
            query += " AND claim_type = ?"
            params.append(claim_type)
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    # --- Skill Verification Runs & Gating Operations ---
    def save_skill_verification_run(self, skill_name: str, skill_version: str = "1.0.0",
                                   source_reports: str = "[]", evidence_refs: str = "[]",
                                   verification_status: str = "unverified", test_status: str = "pending",
                                   test_output: str = "", approval_status: str = "pending_review") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO skill_verification_runs (
                skill_name, skill_version, source_reports, evidence_refs,
                verification_status, test_status, test_output, approval_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (skill_name, skill_version, source_reports, evidence_refs,
              verification_status, test_status, test_output, approval_status, now))
        
        # Sync with agent_skills table
        cursor.execute("""
            UPDATE agent_skills 
            SET skill_version = ?, source_reports = ?, evidence_refs = ?,
                verification_status = ?, test_status = ?, approval_status = ?
            WHERE skill_name = ?
        """, (skill_version, source_reports, evidence_refs, verification_status, test_status, approval_status, skill_name))
        self.conn.commit()
        return cursor.lastrowid

    def get_skill_verification_runs(self, skill_name: Optional[str] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        if skill_name:
            cursor.execute("SELECT * FROM skill_verification_runs WHERE skill_name = ? ORDER BY id DESC", (skill_name,))
        else:
            cursor.execute("SELECT * FROM skill_verification_runs ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]

    def update_skill_approval(self, skill_name: str, approval_status: str,
                              reviewer: str = "SOC Analyst", reason: str = "") -> bool:
        cursor = self.conn.cursor()
        cursor.execute("UPDATE agent_skills SET approval_status = ? WHERE skill_name = ?", (approval_status, skill_name))
        cursor.execute("UPDATE skill_verification_runs SET approval_status = ? WHERE skill_name = ?", (approval_status, skill_name))
        
        cursor.execute("SELECT id FROM agent_skills WHERE skill_name = ?", (skill_name,))
        row = cursor.fetchone()
        skill_id = row["id"] if row else 0
        self.save_approval_record("skill", skill_id, reviewer, approval_status, reason)
        self.conn.commit()
        return True

    # --- Approval Records Operations ---
    def save_approval_record(self, entity_type: str, entity_id: int, reviewer: str,
                             decision: str, reason: str = "") -> int:
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO approval_records (entity_type, entity_id, reviewer, decision, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (entity_type, entity_id, reviewer, decision, reason, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_approval_records(self, entity_type: Optional[str] = None, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM approval_records WHERE 1=1"
        params: List[Any] = []
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_id is not None:
            query += " AND entity_id = ?"
            params.append(entity_id)
        query += " ORDER BY id DESC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

    # --- Stale Run Cleanup: dọn run bị kẹt khi tiến trình bị tắt giữa chừng ---
    def fail_stale_runs(self, reason: str = "Tiến trình bị gián đoạn do khởi động lại dịch vụ.") -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT run_id FROM agent_runs WHERE status = 'running'")
        stale = [r["run_id"] for r in cursor.fetchall()]
        if not stale:
            return 0
        now = datetime.now().isoformat()
        for run_id in stale:
            cursor.execute(
                "UPDATE agent_runs SET status = ?, end_time = ?, result = ? WHERE run_id = ?",
                ("failed", now, reason, run_id)
            )
            try:
                self.log_event(run_id=run_id, event_type="run_stale_cleanup", status="error",
                               summary=reason, error_code="STALE_RUN_CLEANUP")
            except Exception:
                pass  # log_event dùng commit riêng; không được làm hỏng cleanup
        self.conn.commit()
        return len(stale)

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class IOC(BaseModel):
    value: str
    type: str = Field(description="Loại IoC, ví dụ: ipv4, domain, sha256, md5, cve")
    context: Optional[str] = Field(None, description="Bối cảnh xuất hiện của IoC này trong báo cáo")
    ttl_days: Optional[int] = Field(14, description="Thời hạn sử dụng còn giá trị phòng thủ thực tế (TTL tính theo ngày)")
    expires_at: Optional[str] = Field(None, description="Thời điểm hết hạn hiệu lực phòng thủ")
    is_expired: bool = Field(False, description="Đã hết hạn vòng đời kỹ thuật chưa")
    source_type: Optional[str] = Field("tactical", description="Nguồn gốc IoC: tactical_feed hoặc narrative_news")

class MitreTechnique(BaseModel):
    technique_id: str = Field(description="Mã kỹ thuật MITRE, ví dụ: T1105")
    name: str = Field(description="Tên kỹ thuật")
    confidence: str = Field(description="Độ tin cậy: confirmed, candidate, uncertain, not_mapped")
    evidence: str = Field(description="Trích dẫn bằng chứng từ bài báo để chứng minh")

class CTIAnalysisResult(BaseModel):
    status: str = Field(description="Trạng thái: success, partial, failed, insufficient_evidence")
    feed_category: Optional[str] = Field("narrative_news", description="Loại nguồn: tactical_feed (thuần IoC) hoặc narrative_news (báo chí tường thuật)")
    iocs: List[IOC] = Field(default_factory=list)
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    cves_identified: List[str] = Field(default_factory=list, description="Danh sách CVE được phát hiện trong bài")
    threat_actors: List[str] = Field(default_factory=list, description="Nhóm tin tặc / tác nhân tấn công")
    malware_families: List[str] = Field(default_factory=list, description="Mã độc hoặc công cụ độc hại")
    external_references: List[str] = Field(default_factory=list, description="Các đường dẫn trỏ tới báo cáo kỹ thuật gốc (Whitepaper/GitHub)")
    sigma_rules_generated: int = 0
    soc_recommendations: Optional[str] = Field(None, description="Khuyến nghị giám sát / săn lùng mối đe dọa cho SOC")
    missing_evidence: Optional[str] = None

# --- xAI & Trust Verification Schemas ---

class SourceDocument(BaseModel):
    source_url: str
    source_title: str = ""
    source_publisher: Optional[str] = None
    published_at: Optional[str] = None
    fetched_at: str
    http_status: int = 200
    content_hash: str
    raw_content: str
    fetch_status: str = "success"  # 'success', 'http_error', 'unreachable', 'empty_content'
    fetch_error: Optional[str] = None

class EvidenceRecord(BaseModel):
    report_id: Optional[int] = None
    evidence_type: str  # 'ioc', 'claim', 'ttp', 'cve'
    entity_value: str
    exact_quote: str
    char_offset_start: int = -1
    char_offset_end: int = -1
    quote_hash: str = ""
    context_window: str = ""

class IOCVerificationResult(BaseModel):
    indicator: str
    indicator_type: str
    source_url: str
    evidence_quote: str = ""
    evidence_location: str = ""  # e.g., 'offset: 120-135'
    source_match_status: str  # 'exact_match', 'normalized_match', 'not_found'
    context_assessment: str = ""
    maliciousness_status: str  # 'maliciousness_confirmed', 'mentioned_not_confirmed', 'example_or_benign', 'insufficient_evidence', 'conflicting_evidence'
    external_verification_status: str = "unverified"  # 'cisa_known', 'abuse_ch_confirmed', 'unverified'
    verification_notes: str = ""
    trust_score: float = 0.0
    trust_status: str = "unverified"  # 'verified', 'partially_verified', 'unverified', 'rejected'
    approval_status: str = "pending_review"  # 'approved', 'rejected', 'pending_review'

class ClaimVerificationResult(BaseModel):
    claim: str
    claim_type: str  # 'mitre_attack', 'cve', 'threat_actor', 'malware', 'defense_recommendation'
    source_url: str
    evidence_quote: str = ""
    evidence_location: str = ""
    reasoning_summary: str = ""
    verification_status: str  # 'verified', 'insufficient_evidence', 'rejected'
    uncertainties: str = ""
    supporting_references: List[str] = Field(default_factory=list)
    trust_score: float = 0.0

class SkillVerificationResult(BaseModel):
    skill_name: str
    skill_version: str = "1.0.0"
    source_reports: List[int] = Field(default_factory=list)
    evidence_refs: List[int] = Field(default_factory=list)
    verification_status: str = "unverified"  # 'verified', 'unverified', 'rejected'
    test_status: str = "pending"  # 'passed', 'failed', 'syntax_error', 'pending'
    test_output: str = ""
    approval_status: str = "pending_review"  # 'approved', 'rejected', 'pending_review'


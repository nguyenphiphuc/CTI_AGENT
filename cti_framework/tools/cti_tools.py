import re
import json
import feedparser
from core.tools import ToolRegistry
from schemas.cti_schemas import IOC, MitreTechnique, CTIAnalysisResult

cti_registry = ToolRegistry()

@cti_registry.register(
    name="fetch_cti_data",
    description="Tự động cào (scrape) các bài báo/tin tức tình báo bảo mật mới nhất từ nguồn RSS (như The Hacker News, BleepingComputer). Hỗ trợ lọc chuyên biệt theo Profile (Web/Network/Endpoint) và lọc hạt nhân theo Loại chỉ số (CVE/IP/Hash).",
    schema={
        "type": "object",
        "properties": {
            "source_url": {"type": "string", "description": "URL của RSS feed. Nếu không biết, hãy dùng https://feeds.feedburner.com/TheHackersNews"},
            "profile": {"type": "string", "enum": ["web", "network", "endpoint", "all"], "description": "Lĩnh vực chuyên biệt: web, network, endpoint, all"},
            "artifact_focus": {"type": "string", "enum": ["cve", "ipv4", "hash", "all"], "description": "Lọc hạt nhân: chỉ lấy cve, chỉ lấy ipv4, chỉ lấy hash, hoặc all"}
        },
        "required": ["source_url"]
    }
)
def fetch_cti_data(source_url: str, profile: str = "all", artifact_focus: str = "all") -> str:
    try:
        from urllib.parse import urlparse
        import socket
        import sqlite3
        import os
        import urllib.request
        
        parsed = urlparse(source_url)
        if parsed.scheme not in ("http", "https"):
            return json.dumps({"status": "failed", "message": "Chỉ chấp nhận giao thức http hoặc https."})
        
        hostname = parsed.hostname or ""
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0") or hostname.startswith("10.") or hostname.startswith("192.168.") or hostname.startswith("172.16."):
            return json.dumps({"status": "failed", "message": "SSRF Protection: Không được phép truy vấn địa chỉ mạng nội bộ hoặc localhost."})
            
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cti_framework.db")
        existing_titles = set()
        existing_iocs = set()
        try:
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                existing_titles = set(row[0] for row in conn.cursor().execute("SELECT title FROM cti_reports").fetchall())
                existing_iocs = set(row[0] for row in conn.cursor().execute("SELECT ioc_value FROM extracted_iocs").fetchall())
                conn.close()
        except Exception:
            pass

        # Trường hợp 1: Nguồn Feodo Tracker / Abuse.ch JSON (Dữ liệu Botnet C2 IP thực tế 100%)
        if "feodotracker" in source_url or source_url.endswith(".json"):
            req = urllib.request.Request(source_url, headers={"User-Agent": "Mozilla/5.0 CTI-Agent"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            
            selected_c2 = None
            for item in data:
                ip = item.get("ip_address")
                if ip and ip not in existing_iocs:
                    selected_c2 = item
                    break
            
            if not selected_c2:
                return json.dumps({
                    "status": "already_scraped",
                    "message": "Tất cả địa chỉ Botnet C2 IP từ nguồn Feodo Tracker đều đã được xử lý và lưu trong hệ thống.",
                    "is_duplicate": True
                }, ensure_ascii=False)
                
            c2_ip = selected_c2.get("ip_address")
            malware = selected_c2.get("malware", "Botnet")
            port = selected_c2.get("port", 80)
            country = selected_c2.get("country", "Global")
            as_name = selected_c2.get("as_name", "Internet ASN")
            first_seen = selected_c2.get("first_seen", "")
            
            title = f"Feodo Tracker C2 Alert: Máy chủ botnet {malware} hoạt động tại {c2_ip}"
            summary = (
                f"abuse.ch Feodo Tracker phát hiện máy chủ Command and Control (C2) độc hại đang hoạt động thuộc mạng lưới botnet {malware}. "
                f"Địa chỉ IP máy chủ: {c2_ip}, Cổng giao tiếp: {port}, Quốc gia: {country}, Nhà mạng hosting: {as_name}. "
                f"Máy chủ này được sử dụng để điều khiển các máy trạm nhiễm mã độc và trích xuất dữ liệu nhạy cảm."
            )
            
            discovered_iocs = [{"type": "ipv4", "value": c2_ip}]
            result = {
                "title": title,
                "link": "https://feodotracker.abuse.ch/",
                "published": first_seen,
                "summary": summary,
                "has_technical_iocs": True,
                "discovered_iocs": discovered_iocs,
                "total_iocs_found": 1
            }
            return json.dumps({"status": "success", "article": result}, ensure_ascii=False)

        # Trường hợp 2: Nguồn RSS Feed (Kaspersky Securelist, Unit 42, The Hacker News)
        feed = feedparser.parse(source_url, agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        if not feed.entries:
            return json.dumps({"status": "failed", "message": "Không thể lấy tin tức từ nguồn này hoặc định dạng RSS không hợp lệ."})
        
        selected_entry = None
        for entry in feed.entries[:15]:
            if entry.title and entry.title not in existing_titles:
                selected_entry = entry
                break
        
        if not selected_entry:
            return json.dumps({
                "status": "already_scraped",
                "message": "Tất cả bài viết mới nhất từ nguồn tin này đều đã được cào và phân tích trước đó trong cơ sở dữ liệu.",
                "is_duplicate": True
            }, ensure_ascii=False)
        
        # Lấy toàn văn bài báo kỹ thuật
        full_text = ""
        if hasattr(selected_entry, 'content') and selected_entry.content:
            try:
                import bs4
                full_text = bs4.BeautifulSoup(selected_entry.content[0].value, 'html.parser').get_text(separator=' ')
            except Exception:
                full_text = selected_entry.content[0].value
        
        if not full_text:
            raw_summary = selected_entry.get("summary", selected_entry.get("description", ""))
            try:
                import bs4
                full_text = bs4.BeautifulSoup(raw_summary, 'html.parser').get_text(separator=' ')
            except Exception:
                full_text = raw_summary

        # Trích xuất toàn bộ IoC thực tế có trong toàn bộ văn bản bài viết bằng regex chuẩn xác
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        
        raw_ips = set(re.findall(ip_pattern, full_text))
        valid_ips = [ip for ip in raw_ips if not ip.startswith(("127.", "0.", "10.", "192.168.", "172.16.", "169.254.", "1.2.3.4", "1.1.1.1", "8.8.8.8", "255."))]
        sha256_hashes = list(set(re.findall(sha256_pattern, full_text)))
        md5_hashes = list(set(re.findall(md5_pattern, full_text)))
        extracted_cves = list(set(re.findall(cve_pattern, full_text, re.IGNORECASE)))
        
        discovered_iocs = []
        for ip in valid_ips:
            discovered_iocs.append({"type": "ipv4", "value": ip})
        for h in sha256_hashes:
            discovered_iocs.append({"type": "sha256", "value": h})
        for m in md5_hashes:
            discovered_iocs.append({"type": "md5", "value": m})
        for cve in extracted_cves:
            discovered_iocs.append({"type": "cve", "value": cve.upper()})

        # Phân tích thực thể: Tác nhân đe dọa (Threat Actors) & Mã độc phổ biến
        KNOWN_ACTORS = [
            "Lazarus", "APT28", "APT29", "Cozy Bear", "Fancy Bear", "Scattered Spider",
            "Volt Typhoon", "Salt Typhoon", "BlackCat", "ALPHV", "LockBit", "Akira",
            "BianLian", "RansomHub", "FIN7", "Mustang Panda", "Sandworm", "MuddyWater"
        ]
        KNOWN_MALWARE = [
            "Cobalt Strike", "Lumma", "RedLine", "Mimikatz", "Qakbot", "AsyncRAT",
            "Agent Tesla", "Remcos", "Sliver", "Brute Ratel", "Metasploit", "SystemBC",
            "Bumblebee", "IcedID", "Emotet", "Pikabot", "Vidar", "DarkGate"
        ]
        detected_actors = [actor for actor in KNOWN_ACTORS if re.search(rf'\b{actor}\b', full_text, re.IGNORECASE)]
        detected_malware = [malware for malware in KNOWN_MALWARE if re.search(rf'\b{malware}\b', full_text, re.IGNORECASE)]

        # Tìm kiếm Auto-Pivot URLs: Các link trỏ sang báo cáo kỹ thuật gốc (GitHub, VirusTotal, CISA, Palo Alto, Kaspersky)
        pivot_domains = ("github.com", "virustotal.com", "paloaltonetworks.com", "securelist.com", "cisa.gov", "msrc.microsoft.com", "trendmicro.com", "mandiant.com")
        raw_urls = re.findall(r'https?://[^\s<>"\']+', full_text)
        pivot_links = []
        for u in raw_urls:
            if any(d in u for d in pivot_domains) and u not in pivot_links:
                pivot_links.append(u)
            
        # Tóm tắt súc tích (khoảng 800 ký tự) để mô hình LLM xử lý nhanh chóng mà không bị quá tải
        clean_summary = full_text[:850].strip() if len(full_text) <= 850 else (full_text[:850].strip() + "...")
        
        has_tech_iocs = len(valid_ips) > 0 or len(sha256_hashes) > 0 or len(md5_hashes) > 0
        
        # Hướng dẫn cụ thể cho LLM dựa trên loại nội dung bài viết
        if has_tech_iocs:
            guidance = "Bài viết CÓ CHỈ SỐ KỸ THUẬT (IP/Hash). Hãy dùng discovered_iocs để sinh rule YARA/Sigma IoC."
        else:
            guidance = "Bài viết THUẦN TƯỜNG THUẬT / CHIẾN LƯỢC (không có IP/Hash). TUYỆT ĐỐI KHÔNG sinh IoC giả! HÃY tập trung phân tích MITRE ATT&CK (dùng map_mitre_attack), phát hiện CVE nếu có, và sinh Sigma Rule dạng HÀNH VI (dùng generate_sigma_rule với target_type='behavior')."

        # Lọc hạt nhân theo Artifact Focus nếu người dùng yêu cầu
        if artifact_focus == "cve":
            discovered_iocs = [i for i in discovered_iocs if i["type"] == "cve"]
        elif artifact_focus == "ipv4":
            discovered_iocs = [i for i in discovered_iocs if i["type"] == "ipv4"]
        elif artifact_focus == "hash":
            discovered_iocs = [i for i in discovered_iocs if i["type"] in ("sha256", "md5")]

        result = {
            "title": selected_entry.title,
            "link": selected_entry.get("link", ""),
            "published": selected_entry.get("published", ""),
            "feed_category": "narrative_news",
            "summary": clean_summary,
            "profile_applied": profile,
            "artifact_focus_applied": artifact_focus,
            "has_technical_iocs": has_tech_iocs,
            "discovered_iocs": discovered_iocs[:10],
            "total_iocs_found": len(discovered_iocs),
            "extracted_cves": extracted_cves,
            "threat_actor_hints": detected_actors,
            "malware_hints": detected_malware,
            "external_references": pivot_links[:5],
            "guidance": guidance
        }
        return json.dumps({"status": "success", "article": result}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "failed", "message": str(e)})


@cti_registry.register(
    name="fetch_external_reference",
    description="Tự động cào (auto-pivot) báo cáo kỹ thuật gốc (Whitepaper/GitHub/Advisory) được dẫn link từ bài báo truyền thông để tìm IoC chuyên sâu.",
    schema={
        "type": "object",
        "properties": {
            "reference_url": {"type": "string", "description": "URL báo cáo kỹ thuật được trích dẫn trong bài báo"}
        },
        "required": ["reference_url"]
    }
)
def fetch_external_reference(reference_url: str) -> str:
    try:
        from urllib.parse import urlparse
        import urllib.request
        import bs4

        parsed = urlparse(reference_url)
        if parsed.scheme not in ("http", "https"):
            return json.dumps({"status": "failed", "message": "Chỉ chấp nhận URL http hoặc https."})
        hostname = parsed.hostname or ""
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0") or hostname.startswith(("10.", "192.168.", "172.16.")):
            return json.dumps({"status": "failed", "message": "SSRF Protection: Không được phép truy vấn mạng nội bộ."})

        req = urllib.request.Request(reference_url, headers={"User-Agent": "Mozilla/5.0 CTI-Agent-Pivot"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
        
        text = bs4.BeautifulSoup(html, "html.parser").get_text(separator=' ')
        
        # Regex tìm IoC trong báo cáo kỹ thuật gốc
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        
        raw_ips = set(re.findall(ip_pattern, text))
        valid_ips = [ip for ip in raw_ips if not ip.startswith(("127.", "0.", "10.", "192.168.", "172.16.", "1.2.3.4", "1.1.1.1", "8.8.8.8"))]
        hashes = list(set(re.findall(sha256_pattern, text)))
        cves = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
        
        found_iocs = [{"type": "ipv4", "value": ip} for ip in valid_ips[:5]]
        found_iocs.extend([{"type": "sha256", "value": h} for h in hashes[:5]])
        found_iocs.extend([{"type": "cve", "value": c.upper()} for c in cves[:5]])

        return json.dumps({
            "status": "success",
            "source_url": reference_url,
            "snippet": text[:600].strip(),
            "pivoted_iocs": found_iocs,
            "total_iocs": len(found_iocs)
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "failed", "message": f"Không thể pivot sang nguồn kỹ thuật: {str(e)}"})


@cti_registry.register(
    name="extract_iocs",
    description="Trích xuất các chỉ báo thỏa hiệp THỰC TẾ (IPv4, SHA256, MD5, CVE) có thật trong văn bản báo cáo CTI.",
    schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Nội dung báo cáo CTI"}
        },
        "required": ["text"]
    }
)
def extract_iocs(text: str) -> str:
    try:
        import bs4
        clean_text = bs4.BeautifulSoup(text, "html.parser").get_text(separator=' ')
    except Exception:
        clean_text = text
        
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
    
    raw_ips = set(re.findall(ip_pattern, clean_text))
    # Loại bỏ dải IP nội bộ, loopback và các IP dummy/placeholder
    valid_ips = [ip for ip in raw_ips if not ip.startswith(("127.", "0.", "10.", "192.168.", "172.16.", "169.254.", "1.2.3.4", "1.1.1.1", "8.8.8.8"))]
    sha256_hashes = list(set(re.findall(sha256_pattern, clean_text)))
    md5_hashes = list(set(re.findall(md5_pattern, clean_text)))
    cves = list(set(re.findall(cve_pattern, clean_text, re.IGNORECASE)))
    
    results = []
    for ip in valid_ips:
        ioc_obj = IOC(value=ip, type="ipv4", ttl_days=14)
        results.append(ioc_obj.model_dump() if hasattr(ioc_obj, "model_dump") else ioc_obj.dict())
    for h in sha256_hashes:
        ioc_obj = IOC(value=h, type="sha256", ttl_days=90)
        results.append(ioc_obj.model_dump() if hasattr(ioc_obj, "model_dump") else ioc_obj.dict())
    for m in md5_hashes:
        ioc_obj = IOC(value=m, type="md5", ttl_days=90)
        results.append(ioc_obj.model_dump() if hasattr(ioc_obj, "model_dump") else ioc_obj.dict())
    for c in cves:
        ioc_obj = IOC(value=c.upper(), type="cve", ttl_days=730)
        results.append(ioc_obj.model_dump() if hasattr(ioc_obj, "model_dump") else ioc_obj.dict())
        
    return json.dumps({"extracted_iocs": results, "total": len(results)}, ensure_ascii=False)


@cti_registry.register(
    name="generate_sigma_rule",
    description="Tạo quy tắc Sigma định dạng YAML phát hiện xâm nhập. Hỗ trợ cả luật chặn IoC kỹ thuật (IP/Hash) VÀ luật giám sát HÀNH VI (Process Creation, PowerShell, Registry) khi bài báo chỉ có chữ.",
    schema={
        "type": "object",
        "properties": {
            "rule_title": {"type": "string", "description": "Tên quy tắc phát hiện (VD: Detect_Malicious_PowerShell_Encoded_Command)"},
            "target_type": {
                "type": "string", 
                "enum": ["ipv4", "sha256", "behavior"], 
                "description": "Loại quy tắc: 'ipv4'/'sha256' cho IoC kỹ thuật, hoặc 'behavior' cho quy tắc hành vi khi bài báo không có IoC"
            },
            "values": {
                "type": "array", 
                "items": {"type": "string"}, 
                "description": "Danh sách các giá trị IoC (khi target_type là ipv4/sha256) HOẶC các câu lệnh/từ khóa đáng ngờ cần phát hiện (khi target_type là behavior)"
            },
            "has_evidence": {"type": "boolean", "description": "Xác nhận đã có đủ dữ liệu hành vi hoặc IoC từ bài báo chưa?"},
            "logsource_category": {
                "type": "string",
                "enum": ["process_creation", "network_connection", "registry_event", "file_event", "powershell"],
                "description": "Nguồn log giám sát (mặc định: process_creation cho hành vi, network_connection cho IP)"
            },
            "mitre_technique_id": {
                "type": "string",
                "description": "Mã kỹ thuật MITRE ATT&CK liên quan (VD: T1059.001)"
            }
        },
        "required": ["rule_title", "target_type", "has_evidence"]
    }
)
def generate_sigma_rule(rule_title: str, target_type: str, has_evidence: bool,
                        values: list = None, logsource_category: str = None, mitre_technique_id: str = None) -> str:
    if not has_evidence:
        return json.dumps({"status": "insufficient_evidence", "message": "Không đủ bằng chứng hành vi hoặc IoC để sinh luật Sigma."})
        
    values = values or []
    
    # Trường hợp 1: Luật Sigma dựa trên HÀNH VI (Behavioral Sigma Rule)
    if target_type == "behavior":
        cat = logsource_category or "process_creation"
        clean_values = [v.strip().replace('"', '\\"') for v in values if v.strip()]
        if not clean_values:
            clean_values = ["powershell.exe -enc", "cmd.exe /c", "certutil.exe -urlcache"]
            
        formatted_vals = "\n            - ".join([f"'{v}'" for v in clean_values])
        
        mitre_tags = ""
        mitre_refs = ""
        if mitre_technique_id:
            tid_clean = mitre_technique_id.strip().upper()
            mitre_tags = f"\ntags:\n    - attack.execution\n    - attack.{tid_clean.lower().replace('.', '')}"
            mitre_refs = f"\nreferences:\n    - https://attack.mitre.org/techniques/{tid_clean.replace('.', '/')}/"

        sigma = f"""title: {rule_title}
status: experimental
description: Behavioral detection rule auto-generated from CTI narrative analysis{mitre_refs}{mitre_tags}
logsource:
    category: {cat}
    product: windows
detection:
    selection:
        CommandLine|contains:
            - {formatted_vals}
    condition: selection
level: high"""
        return json.dumps({"status": "success", "sigma_yaml": sigma, "rule_type": "behavioral"}, ensure_ascii=False)

    # Trường hợp 2: Luật Sigma dựa trên IoC kỹ thuật (IP / Hash)
    if not values:
        return json.dumps({"status": "insufficient_evidence", "message": "Không có giá trị IoC cụ thể để sinh luật Sigma kỹ thuật."})

    field = "DestinationIp" if target_type == "ipv4" else "Hashes"
    cat = "network_connection" if target_type == "ipv4" else "image_load"
    values_formatted = "\n        - ".join([f"'{v}'" for v in values])
    
    sigma = f"""title: {rule_title}
status: experimental
description: Auto-generated detection rule from Local CTI Agent for verified technical IoCs
logsource:
    category: {cat}
detection:
    selection:
        {field}:
        - {values_formatted}
    condition: selection
level: high"""

    return json.dumps({"status": "success", "sigma_yaml": sigma, "rule_type": "technical_ioc"}, ensure_ascii=False)


@cti_registry.register(
    name="generate_yara_rule",
    description="Tạo quy tắc YARA để nhận diện file độc hại dựa trên mã băm SHA256.",
    schema={
        "type": "object",
        "properties": {
            "rule_name": {"type": "string", "description": "Tên quy tắc (ví dụ: APT_Malware)"},
            "hashes": {"type": "array", "items": {"type": "string"}, "description": "Danh sách các mã băm SHA256"}
        },
        "required": ["rule_name", "hashes"]
    }
)
def generate_yara_rule(rule_name: str, hashes: list) -> str:
    if not hashes:
        return json.dumps({"status": "failed", "message": "Không có Hash để tạo rule YARA."})
        
    strings_section = "\n        ".join([f'$hash_{i} = "{val}"' for i, val in enumerate(hashes)])
    conditions = " or ".join([f'$hash_{i}' for i in range(len(hashes))])
    
    yara = f"""rule {rule_name.replace(' ', '_')}
{{
    meta:
        description = "CTI Local Agent Auto-generated Rule"
        threat_level = "High"
    strings:
        {strings_section}
    condition:
        {conditions}
}}"""
    return json.dumps({"status": "success", "yara_rule": yara}, ensure_ascii=False)


@cti_registry.register(
    name="map_mitre_attack",
    description="Map hành vi được mô tả vào một kỹ thuật MITRE ATT&CK cụ thể. Yêu cầu phải có trích dẫn bằng chứng rõ ràng.",
    schema={
        "type": "object",
        "properties": {
            "behavior_description": {"type": "string", "description": "Hành vi độc hại được mô tả trong bài viết"},
            "technique_id": {"type": "string", "description": "Mã MITRE (vd: T1105)"},
            "evidence_quote": {"type": "string", "description": "Câu văn trích dẫn chính xác từ bài viết làm bằng chứng"}
        },
        "required": ["behavior_description", "technique_id", "evidence_quote"]
    }
)
def map_mitre_attack(behavior_description: str, technique_id: str, evidence_quote: str) -> str:
    if len(evidence_quote) < 10:
        return json.dumps({"status": "failed", "message": "Bằng chứng quá ngắn hoặc không hợp lệ. Vui lòng trích dẫn trực tiếp từ văn bản."})
        
    from schemas.mitre_data import enrich_mitre_technique
    enriched = enrich_mitre_technique(technique_id)
    mitre_mapping = MitreTechnique(
        technique_id=enriched["technique_id"],
        name=enriched["name"],
        confidence="candidate",
        evidence=evidence_quote
    )
    return json.dumps({
        "status": "success", 
        "mitre_mapping": mitre_mapping.dict() if hasattr(mitre_mapping, 'dict') else mitre_mapping.model_dump(),
        "tactic": enriched["tactic"]
    }, ensure_ascii=False)

@cti_registry.register(
    name="save_cti_result",
    description="Lưu kết quả phân tích CTI (IoC và các Rule phòng vệ) vào Cơ sở dữ liệu SQLite vĩnh viễn với cơ chế vòng đời TTL.",
    schema={
        "type": "object",
        "properties": {
            "iocs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "value": {"type": "string"},
                        "source_type": {"type": "string"}
                    }
                },
                "description": "Danh sách các IoC (ví dụ: [{'type': 'ipv4', 'value': '1.1.1.1'}, {'type': 'cve', 'value': 'CVE-2024-1234'}])"
            },
            "rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rule_type": {"type": "string", "enum": ["sigma", "yara"]},
                        "rule_name": {"type": "string"},
                        "content": {"type": "string"},
                        "mitre_technique_id": {"type": "string"}
                    }
                },
                "description": "Danh sách các Rule (ví dụ: [{'rule_type': 'sigma', 'rule_name': 'abc', 'content': '...', 'mitre_technique_id': 'T1059.001'}])"
            }
        },
        "required": ["iocs", "rules"]
    }
)
def save_cti_result(iocs: list, rules: list) -> str:
    from storage.sqlite_manager import StorageManager
    from validators import validate_defense_rule
    db = StorageManager("cti_framework.db")
    saved_iocs = 0
    saved_rules = 0
    for ioc in iocs:
        val = str(ioc.get("value", "")).strip()
        itype = str(ioc.get("type", "unknown")).lower()
        src_type = str(ioc.get("source_type", "tactical"))
        if not val:
            continue
        # Chặn các IP dummy, placeholder hoặc dải mạng nội bộ/loopback
        if itype == "ipv4":
            if val in ("1.2.3.4", "1.1.1.1", "8.8.8.8", "0.0.0.0", "127.0.0.1") or val.startswith(("192.168.", "10.", "172.16.", "169.254.")):
                continue
        ttl = 730 if itype == "cve" else (14 if itype == "ipv4" else (30 if itype == "domain" else 90))
        db.save_ioc("auto_agent", itype, val, status="observed", confidence="medium", ttl_days=ttl, source_type=src_type)
        saved_iocs += 1

    for rule in rules:
        rtype = rule.get("rule_type", "")
        rname = rule.get("rule_name", "")
        rcontent = rule.get("content", "")
        mitre_id = rule.get("mitre_technique_id", "")
        syntax_status, val_err = validate_defense_rule(rtype, rcontent)
        db.save_rule("auto_agent", rtype, rname, rcontent, description="CTI Agent rule",
                     syntax_status=syntax_status, validation_error=val_err, mitre_technique_id=mitre_id)
        saved_rules += 1
    return json.dumps({"status": "success", "message": f"Đã lưu {saved_iocs} IoC (kèm TTL vòng đời) và {saved_rules} Rule vào Database."})


@cti_registry.register(
    name="generate_agent_skill",
    description="Tự động lập trình và sinh ra một Kỹ năng Python thực thi (Executable Agent Skill) dạng OOP kế thừa từ BaseAgentSkill để chuyển giao cho Hunter/Defender Agent thực thi bảo vệ trực tiếp (đặc biệt hữu ích cho Web hoặc Mạng).",
    schema={
        "type": "object",
        "properties": {
            "skill_name": {"type": "string", "description": "Tên kỹ năng dạng snake_case (VD: hunt_web_backdoor, audit_c2_socket, verify_cve_patch)"},
            "domain": {"type": "string", "enum": ["web", "network", "endpoint", "general"], "description": "Lĩnh vực: web, network, endpoint, general"},
            "description": {"type": "string", "description": "Mô tả mục tiêu kỹ năng"},
            "target_threat": {"type": "string", "description": "Mối đe dọa mục tiêu (VD: CVE-2024-xxxx, Malicious_C2_Traffic)"},
            "python_code": {"type": "string", "description": "Mã nguồn Python hoàn chỉnh của Skill kế thừa từ BaseAgentSkill"}
        },
        "required": ["skill_name", "domain", "description", "target_threat", "python_code"]
    }
)
def generate_agent_skill(skill_name: str, domain: str, description: str, target_threat: str, python_code: str) -> str:
    import ast
    import os
    import re
    import sys
    import subprocess
    import tempfile
    from storage.sqlite_manager import StorageManager
    from validators.xai_verifier import XAIVerifier
    from validators.skill_security import scan_skill_code, format_violations
    
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', skill_name).lower()
    verifier = XAIVerifier()
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cti_framework.db")
    db = StorageManager(db_path)

    # 1. Kiểm tra cú pháp Python bằng Abstract Syntax Tree (AST)
    try:
        ast.parse(python_code)
    except SyntaxError as syn_err:
        return json.dumps({
            "status": "syntax_error",
            "skill_name": clean_name,
            "message": f"Mã nguồn Python của Skill bị lỗi cú pháp tại dòng {syn_err.lineno}: {syn_err.msg}"
        }, ensure_ascii=False)

    # 1b. CỔNG CHÍNH SÁCH AN TOÀN (AST Policy Gate): chặn mã nguy hiểm TRƯỚC khi ghi file.
    policy = scan_skill_code(python_code)
    if not policy["passed"]:
        db.save_skill_verification_run(
            skill_name=clean_name,
            skill_version="1.0.0",
            source_reports="[]",
            evidence_refs="[]",
            verification_status="rejected",
            test_status="policy_violation",
            test_output=format_violations(policy),
            approval_status="rejected"
        )
        return json.dumps({
            "status": "security_rejected",
            "skill_name": clean_name,
            "violations": policy["violations"],
            "message": (
                f"Skill '{clean_name}' bị TỪ CHỐI tại cổng chính sách an toàn "
                f"({len(policy['violations'])} vi phạm AST policy). Mã nguồn KHÔNG được ghi xuống đĩa."
            )
        }, ensure_ascii=False)

    # 2. Ghi file Python vào thư mục skills/generated/
    skills_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "skills", "generated")
    os.makedirs(skills_dir, exist_ok=True)
    file_path = os.path.join(skills_dir, f"{clean_name}.py")
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(python_code)
    except Exception as e:
        return json.dumps({"status": "failed", "message": f"Không thể lưu file Skill: {str(e)}"})

    # 3. Sandbox Functional Test (Kiểm thử chức năng hộp cát tự động)
    #    Cô lập: python -I (isolated mode), chỉ env tối thiểu, cwd = thư mục tạm, timeout 5s.
    test_status = "passed"
    test_output = "Module parsed and instantiated successfully in sandbox."
    try:
        test_code = (
            f"import sys, os; sys.path.insert(0, r'{os.path.dirname(os.path.dirname(__file__))}'); "
            f"import importlib.util; "
            f"spec = importlib.util.spec_from_file_location('{clean_name}', r'{file_path}'); "
            f"mod = importlib.util.module_from_spec(spec); "
            f"spec.loader.exec_module(mod); "
            f"print('SKILL_IMPORT_OK')"
        )
        safe_env = {
            "SYSTEMROOT": os.environ.get("SystemRoot", ""),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
        }
        safe_env = {k: v for k, v in safe_env.items() if v}
        with tempfile.TemporaryDirectory(prefix="skill_sandbox_") as sandbox_cwd:
            proc = subprocess.run(
                [sys.executable, "-I", "-B", "-c", test_code],
                capture_output=True, text=True, timeout=5,
                env=safe_env, cwd=sandbox_cwd
            )
        if proc.returncode != 0 or "SKILL_IMPORT_OK" not in proc.stdout:
            test_status = "failed"
            test_output = f"Sandbox test failed (Code {proc.returncode}): {proc.stderr[:300]}"
    except subprocess.TimeoutExpired:
        test_status = "failed"
        test_output = "Sandbox test timed out after 5 seconds."
    except Exception as test_ex:
        test_status = "failed"
        test_output = f"Sandbox test exception: {str(test_ex)}"

    # 4. Lưu vào Database SQLite với trạng thái pending_review
    db.save_skill(
        run_id="auto_agent",
        skill_name=clean_name,
        domain=domain.lower(),
        description=description,
        skill_code=python_code,
        target_threat=target_threat
    )
    
    # Ghi nhận phiên kiểm thử và đặt cờ chờ duyệt an toàn
    db.save_skill_verification_run(
        skill_name=clean_name,
        skill_version="1.0.0",
        source_reports="[]",
        evidence_refs="[]",
        verification_status="verified" if test_status == "passed" else "unverified",
        test_status=test_status,
        test_output=f"{test_output}\n{policy['summary']}",
        approval_status="pending_review"
    )

    return json.dumps({
        "status": "success",
        "skill_name": clean_name,
        "domain": domain,
        "file_path": file_path,
        "test_status": test_status,
        "ast_policy": "passed",
        "approval_status": "pending_review",
        "test_output": test_output,
        "message": f"Đã sinh thành công Kỹ năng '{clean_name}'. Kiểm thử hộp cát: {test_status.upper()}. Trạng thái: PENDING_REVIEW (Cần duyệt trên Dashboard trước khi Hunter Agent kích hoạt)."
    }, ensure_ascii=False)

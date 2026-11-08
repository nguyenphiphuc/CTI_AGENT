"""
CTI Domain Profiles & Targeted Pipeline Engine
Phân chia chuyên biệt hóa nguồn và chỉ số CTI theo lĩnh vực:
- web: Dành cho kỹ sư An ninh Web / Lập trình viên Web
- network: Dành cho kỹ sư An ninh Mạng / Hạ tầng
- endpoint: Dành cho kỹ sư Phân tích Mã độc / Endpoint
- all: Chế độ quét toàn diện 360 độ
"""

from typing import Dict, List, Any, Optional

PROFILES: Dict[str, Dict[str, Any]] = {
    "web": {
        "id": "web",
        "name": "Web Application Security",
        "label": "An ninh Ứng dụng Web (Web Security)",
        "description": "Chuyên cào và bóc tách lỗ hổng Web, API, CMS (WordPress, PHP, Nginx, Apache), SQLi, XSS, SSRF, Deserialization, Webshell.",
        "target_entities": ["cve", "url", "domain", "webshell"],
        "rss_sources": [
            {
                "name": "The Hacker News - Web Security Focus",
                "url": "https://feeds.feedburner.com/TheHackersNews",
                "category": "narrative_news",
                "filter_keywords": ["web", "vulnerability", "sql", "xss", "rce", "cve", "apache", "nginx", "php", "wordpress", "api", "bypass", "auth"]
            },
            {
                "name": "Dark Reading - Application Defense",
                "url": "https://www.darkreading.com/rss.xml",
                "category": "narrative_news",
                "filter_keywords": ["appsec", "web", "cloud", "api", "software", "flaw", "patch", "cve"]
            },
            {
                "name": "CISA KEV (Known Exploited Web Vulnerabilities)",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "category": "tactical_feed",
                "filter_keywords": []
            }
        ],
        "default_artifact_focus": "cve",
        "guidance": (
            "CHUYÊN BIỆT HÓA WEB: Tập trung 100% vào các lỗ hổng Web, API, lỗi phân quyền, Webshell, RCE và mã CVE. "
            "Nếu có CVE, hãy bóc tách điểm CVSS và phiên bản bị ảnh hưởng. "
            "Hãy sinh ra Python Skill phòng vệ Web (WebDefenseSkill / HeaderChecker / BackdoorScanner) để phục vụ lập trình viên web."
        )
    },
    "network": {
        "id": "network",
        "name": "Network & Infrastructure Security",
        "label": "Hạ tầng & Kết nối Mạng (Network Security)",
        "description": "Chuyên cào và bóc tách địa chỉ IP Botnet C2, VPN Gateway, Firewall bypass, DDoS, DNS Tunneling, Port Scanning.",
        "target_entities": ["ipv4", "domain", "port", "cidr"],
        "rss_sources": [
            {
                "name": "abuse.ch Feodo Tracker (Botnet C2 IP tươi 100%)",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                "category": "tactical_feed",
                "filter_keywords": []
            },
            {
                "name": "Unit 42 - Palo Alto Networks (Mạng & Tường lửa)",
                "url": "https://unit42.paloaltonetworks.com/feed/",
                "category": "operational_feed",
                "filter_keywords": ["vpn", "firewall", "network", "c2", "traffic", "dns", "ddos"]
            }
        ],
        "default_artifact_focus": "ipv4",
        "guidance": (
            "CHUYÊN BIỆT HÓA MẠNG: Tập trung 100% vào địa chỉ IP máy chủ C2 độc hại, cổng giao tiếp, VPN gateway bị tấn công. "
            "Bóc tách toàn bộ IP/CIDR thật, gán thời hạn TTL 14 ngày. "
            "Hãy sinh ra Python Skill kiểm toán socket mạng (NetworkSocketAuditorSkill) để rà soát kết nối đáng ngờ."
        )
    },
    "endpoint": {
        "id": "endpoint",
        "name": "Endpoint & Malware Analysis",
        "label": "Mã độc & Endpoint (Malware & Host Security)",
        "description": "Chuyên cào và bóc tách mã băm SHA256/MD5, Ransomware, Trojan cửa sau, kỹ thuật LOLBins, Registry persistence.",
        "target_entities": ["sha256", "md5", "yara"],
        "rss_sources": [
            {
                "name": "Kaspersky Securelist (Chuyên sâu Mã độc & APT)",
                "url": "https://securelist.com/feed/",
                "category": "operational_feed",
                "filter_keywords": []
            },
            {
                "name": "SentinelOne Labs (Nghiên cứu Mã độc & Reverse Engineering)",
                "url": "https://www.sentinelone.com/labs/feed/",
                "category": "operational_feed",
                "filter_keywords": []
            }
        ],
        "default_artifact_focus": "hash",
        "guidance": (
            "CHUYÊN BIỆT HÓA ENDPOINT: Tập trung vào mã băm File Hash (SHA256, MD5) và họ mã độc (Malware Family). "
            "Sinh luật YARA nhận diện file độc và luật Sigma tiến trình (Process Creation). "
            "Hãy sinh ra Python Skill quét mã băm file (FileHashAuditorSkill)."
        )
    },
    "all": {
        "id": "all",
        "name": "Universal 360 CTI",
        "label": "Quét Tổng hợp Đa tầng (360-degree Universal CTI)",
        "description": "Quét toàn diện tất cả các nguồn từ Botnet C2, Báo cáo APT đến Tin tức thời sự doanh nghiệp.",
        "target_entities": ["cve", "ipv4", "sha256", "md5", "domain", "url"],
        "rss_sources": [
            {"name": "abuse.ch Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "category": "tactical_feed"},
            {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "category": "narrative_news"},
            {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "category": "operational_feed"},
            {"name": "Unit 42 - Palo Alto Networks", "url": "https://unit42.paloaltonetworks.com/feed/", "category": "operational_feed"},
            {"name": "SentinelOne Labs", "url": "https://www.sentinelone.com/labs/feed/", "category": "operational_feed"},
            {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "category": "operational_feed"},
            {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "category": "narrative_news"},
            {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "narrative_news"}
        ],
        "default_artifact_focus": "all",
        "guidance": "QUÉT TỔNG HỢP: Bóc tách cả IP C2, mã băm, CVE, gán MITRE ATT&CK và tạo cả Rule phòng vệ lẫn Skill hành động."
    }
}

def get_profile(profile_id: str = "all") -> Dict[str, Any]:
    return PROFILES.get(profile_id.lower(), PROFILES["all"])

def get_all_profiles() -> List[Dict[str, Any]]:
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "label": p["label"],
            "description": p["description"],
            "default_artifact_focus": p["default_artifact_focus"],
            "sources_count": len(p["rss_sources"])
        }
        for p in PROFILES.values()
    ]

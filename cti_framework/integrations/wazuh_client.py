import requests
import urllib3
import logging
import os
from typing import List, Dict, Any, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("WazuhIntegration")

class WazuhClient:
    """
    Adapter kết nối và tích hợp CTI Framework với Wazuh SIEM/XDR qua REST API.
    Hỗ trợ:
      - Xác thực JWT token
      - Lấy trạng thái Wazuh Manager và số lượng Agent
      - Đồng bộ IOCs (IP, File Hash) vào Wazuh CDB List (Constant Data Base)
      - Khởi động lại / reload Wazuh Manager khi nạp dữ liệu mới
    """
    def __init__(
        self,
        base_url: str = os.getenv("WAZUH_API_URL", "https://localhost:55000"),
        username: str = os.getenv("WAZUH_API_USER", "wazuh-wui"),
        password: str = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token: Optional[str] = None

    def authenticate(self) -> bool:
        """Lấy JWT token xác thực từ Wazuh API."""
        try:
            url = f"{self.base_url}/security/user/authenticate"
            resp = requests.post(
                url,
                auth=(self.username, self.password),
                verify=False,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("data", {}).get("token")
                return True
            logger.error(f"Wazuh auth failed: HTTP {resp.status_code} - {resp.text}")
            return False
        except Exception as e:
            logger.error(f"Cannot connect to Wazuh API at {self.base_url}: {e}")
            return False

    def _get_headers(self, content_type: Optional[str] = "application/json") -> Dict[str, str]:
        if not self.token:
            if not self.authenticate():
                raise ConnectionError("Không thể xác thực với Wazuh API. Kiểm tra thông tin đăng nhập hoặc container Wazuh.")
        headers = {"Authorization": f"Bearer {self.token}"}
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def get_status(self) -> Dict[str, Any]:
        """Lấy thông tin sức khỏe của Wazuh Manager và tổng quan Agents."""
        try:
            headers = self._get_headers()
            info_resp = requests.get(f"{self.base_url}/manager/info", headers=headers, verify=False, timeout=5)
            if info_resp.status_code == 401:
                # Token hết hạn, thử xác thực lại
                self.token = None
                headers = self._get_headers()
                info_resp = requests.get(f"{self.base_url}/manager/info", headers=headers, verify=False, timeout=5)

            agents_resp = requests.get(f"{self.base_url}/agents/summary/status", headers=headers, verify=False, timeout=5)

            # Đếm số lượng CDB lists hiện có
            lists_resp = requests.get(f"{self.base_url}/lists/files", headers=headers, verify=False, timeout=5)

            info_data = info_resp.json().get("data", {}).get("affected_items", [{}])[0] if info_resp.status_code == 200 else {}
            agents_data = agents_resp.json().get("data", {}).get("connection", {}) if agents_resp.status_code == 200 else {}
            lists_data = lists_resp.json().get("data", {}).get("affected_items", []) if lists_resp.status_code == 200 else []

            # Kiểm tra xem cti_malicious_iocs đã tồn tại trong danh sách lists chưa
            has_cti_list = any(item.get("filename") == "cti_malicious_iocs" for item in lists_data)

            return {
                "connected": True,
                "version": info_data.get("version", "v4.x"),
                "manager_name": info_data.get("name", "wazuh.manager"),
                "agents": {
                    "total": agents_data.get("total", 0),
                    "active": agents_data.get("active", 0),
                    "disconnected": agents_data.get("disconnected", 0),
                    "never_connected": agents_data.get("never_connected", 0)
                },
                "has_cti_list": has_cti_list,
                "total_lists": len(lists_data)
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
                "version": "Offline",
                "agents": {"total": 0, "active": 0, "disconnected": 0, "never_connected": 0},
                "has_cti_list": False
            }

    def sync_iocs(self, iocs: List[Dict[str, Any]], list_name: str = "cti_malicious_iocs") -> Dict[str, Any]:
        """
        Đồng bộ danh sách IOC (IP và SHA256) sang CDB List của Wazuh.
        Định dạng Wazuh CDB: <key>:<value>\n
        Ví dụ:
          198.51.100.1:malicious_c2_ip
          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:malicious_sha256
        """
        if not iocs:
            return {"status": "skipped", "message": "Không có IOC nào để đồng bộ."}

        lines = []
        for item in iocs:
            val = item.get("ioc_value") or item.get("value")
            itype = item.get("ioc_type") or item.get("type", "unknown")
            desc = item.get("confidence") or "malicious"
            if val:
                lines.append(f"{val.strip()}:{itype}_{desc}")

        if not lines:
            return {"status": "skipped", "message": "Không có giá trị IOC hợp lệ."}

        content = "\n".join(lines) + "\n"

        try:
            headers = self._get_headers(content_type="application/octet-stream")
            url = f"{self.base_url}/lists/files/{list_name}?overwrite=true"
            resp = requests.put(
                url,
                data=content.encode("utf-8"),
                headers=headers,
                verify=False,
                timeout=15
            )

            if resp.status_code == 200:
                # Tự động yêu cầu Manager reload hoặc makelists nếu có thể
                return {
                    "status": "success",
                    "synced_count": len(lines),
                    "list_name": list_name,
                    "message": f"Đã đồng bộ thành công {len(lines)} IOCs vào Wazuh CDB List: etc/lists/{list_name}"
                }
            else:
                return {
                    "status": "failed",
                    "status_code": resp.status_code,
                    "message": f"Lỗi từ Wazuh API: {resp.text}"
                }
        except Exception as e:
            return {"status": "failed", "message": f"Lỗi kết nối khi đồng bộ: {str(e)}"}

    def reload_manager(self) -> Dict[str, Any]:
        """Yêu cầu Wazuh Manager biên dịch lại CDB list và reload rules."""
        try:
            headers = self._get_headers()
            resp = requests.put(f"{self.base_url}/manager/restart", headers=headers, verify=False, timeout=20)
            if resp.status_code == 200:
                return {"status": "success", "message": "Wazuh Manager đã khởi động lại để biên dịch rules & CDB lists."}
            else:
                return {"status": "failed", "message": resp.text}
        except Exception as e:
            return {"status": "failed", "message": str(e)}

    def test_log(self, log_line: str) -> Dict[str, Any]:
        """Chạy kiểm thử log qua wazuh-logtest để xem rule nào kích hoạt."""
        import subprocess
        try:
            cmd = ["docker", "exec", "-i", "single-node-wazuh.manager-1", "/var/ossec/bin/wazuh-logtest"]
            res = subprocess.run(cmd, input=f"{log_line.strip()}\n", capture_output=True, text=True, timeout=12)
            output = res.stderr or res.stdout
            fired = "**Alert to be generated." in output
            return {
                "success": res.returncode == 0,
                "fired_alert": fired,
                "output": output
            }
        except Exception as e:
            return {"success": False, "fired_alert": False, "error": str(e)}




# ddns_updater/providers/inwx_provider.py
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class InwxProvider(BaseProvider):
    NAME = "inwx"
    API_HOST = "dyndns.inwx.com"
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('inwx_username')
        self.password = self.config.get('inwx_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (inwx_username, inwx_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 INWX에서 hostname 구성에 필요.
        return ["inwx_username", "inwx_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # INWX API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on INWX using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<password>@dyndns.inwx.com/nic/update
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.password, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
        }
        if record_type == "AAAA": # IPv6
            params['myipv6'] = ip_address
        else: # IPv4 (기본)
            params['myip'] = ip_address
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                # INWX는 DynDNS 표준 오류 코드(badauth, nohost 등)를 반환할 수 있음.
                if "badauth" in response_text.lower():
                    error_message = "API Error: Authentication failed (badauth)."
                elif "nohost" in response_text.lower() or "notfqdn" in response_text.lower():
                     error_message = "API Error: Hostname not found or not a FQDN."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if response_text.lower().startswith("good") or response_text.lower().startswith("nochg"):
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                # INWX 응답은 "good <IP Address>" 또는 "nochg <IP Address>" 형태일 수 있음.
                # IP 추출 및 비교 로직 추가 권장.
                # 여기서는 Go 코드의 단순한 성공 처리(IP 반환)를 따름.
                success_message = f"Successfully updated {hostname_for_query} to {ip_address} (assumed)."
                if response_text:
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            # INWX는 다른 DynDNS 표준 오류 코드도 반환할 수 있음 (예: 'abuse', 'dnserr')
            # Go 코드에는 없지만, API 문서 확인 후 추가 가능
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
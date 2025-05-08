# ddns_updater/providers/strato_provider.py
import requests
from urllib.parse import quote # URL에 도메인/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class StratoProvider(BaseProvider):
    NAME = "strato"
    API_HOST = "dyndns.strato.com"
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.password = self.config.get('strato_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.password, self.domain]): # owner는 기본값 처리
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (strato_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 Strato에서 hostname 구성에 필요.
        return ["strato_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Strato API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Strato (Germany) using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Strato는 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<domain>:<password>@dyndns.strato.com/nic/update
        # Strato는 Userinfo의 username 부분에 도메인 이름을 사용.
        userinfo_user = quote(self.domain, safe='') # 도메인 이름을 URL 인코딩
        userinfo_pass = quote(self.password, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
        }
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                # Strato는 DynDNS 표준 오류 코드(badauth, nohost 등)를 반환할 수 있음.
                # Go 코드의 "constants.Badauth"는 오타로 보이며, 실제로는 "badauth"일 것임.
                if response_text.lower().startswith("notfqdn"):
                    error_message = "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
                elif response_text.lower().startswith("abuse"):
                     error_message = "API Error: Account blocked for abuse."
                elif response_text.lower().startswith("badrequest"):
                     error_message = "API Error: Bad request."
                elif response_text.lower().startswith("badauth"): # "constants.Badauth" 대신 "badauth"
                     error_message = "API Error: Authentication failed (badauth)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if response_text.lower().startswith("notfqdn"):
                return False, "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
            elif response_text.lower().startswith("abuse"):
                return False, "API Error: Account blocked for abuse."
            elif response_text.lower().startswith("badrequest"):
                return False, "API Error: Bad request."
            elif response_text.lower().startswith("badauth"): # "constants.Badauth" 대신 "badauth"
                return False, "API Error: Authentication failed (badauth)."
            elif response_text.lower().startswith("good") or response_text.lower().startswith("nochg"):
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                # Strato 응답은 "good <IP Address>" 또는 "nochg <IP Address>" 형태일 수 있음.
                # IP 추출 및 비교 로직 추가 권장.
                # 여기서는 Go 코드의 단순한 성공 처리(IP 반환)를 따름.
                success_message = f"Successfully updated {hostname_for_query} to {ip_address} (assumed)."
                if response_text:
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
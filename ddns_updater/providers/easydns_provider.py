# ddns_updater/providers/easydns_provider.py
import requests
from urllib.parse import quote # URL에 사용자 이름/토큰 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class EasydnsProvider(BaseProvider):
    NAME = "easydns"
    API_HOST = "api.cp.easydns.com"
    API_PATH = "/dyn/generic.php"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('easydns_username')
        self.token = self.config.get('easydns_token')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.username, self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (easydns_username, easydns_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 EasyDNS에서 hostname 구성에 필요.
        return ["easydns_username", "easydns_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # EasyDNS API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on EasyDNS using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # EasyDNS는 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<token>@api.cp.easydns.com/dyn/generic.php
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.token, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
        }
        
        owner_val = self.config.get('owner', '@')
        if owner_val == '*':
            params['wildcard'] = 'ON'

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 오류 원인이 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                # Go 코드의 오류 문자열 확인 로직 통합
                if "no_service" in response_text.lower():
                    error_message = "API Error: Service not available (no_service)."
                elif "no_access" in response_text.lower():
                    error_message = "API Error: Authentication failed (no_access)."
                elif "illegal_input" in response_text.lower() or "too_soon" in response_text.lower():
                    error_message = "API Error: Input error or update too soon (abuse)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if not response_text: # 빈 응답
                return False, "API Error: Received empty response from server."
            if "no_service" in response_text.lower():
                return False, "API Error: Service not available (no_service)."
            elif "no_access" in response_text.lower():
                return False, "API Error: Authentication failed (no_access)."
            elif "illegal_input" in response_text.lower() or "too_soon" in response_text.lower():
                return False, "API Error: Input error or update too soon (abuse)."
            elif "no_error" in response_text.lower() or "ok" in response_text.lower():
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                # EasyDNS 응답은 "NOERROR - <ip> - <hostname>" 또는 "OK - <ip> - <hostname>" 형태일 수 있음.
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
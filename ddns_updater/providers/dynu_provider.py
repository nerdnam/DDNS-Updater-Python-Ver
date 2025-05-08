# ddns_updater/providers/dynu_provider.py
import requests

from .base_provider import BaseProvider

class DynuProvider(BaseProvider):
    NAME = "dynu"
    API_ENDPOINT = "https://api.dynu.com/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('dynu_username')
        self.password = self.config.get('dynu_password')
        self.group = self.config.get('dynu_group') # 선택적 파라미터
        
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정 (Go 코드 참조)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dynu_username, dynu_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Dynu에서 hostname 구성에 필요.
        return ["dynu_username", "dynu_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Dynu API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"dynu_group": None, "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Dynu Systems using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildDomainName과 동일한 역할 (쿼리용)"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        params = {
            'username': self.username,
            'password': self.password,
            'hostname': hostname_for_query,
        }
        if self.group: # group이 설정된 경우에만 파라미터에 추가
            params['location'] = self.group
        
        if record_type == "AAAA": # IPv6
            params['myipv6'] = ip_address
        else: # IPv4 (기본)
            params['myip'] = ip_address
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # Dynu는 인증 정보를 쿼리 파라미터로 전달 (HTTP Basic Auth 아님)
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 오류 원인이 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                # Go 코드의 오류 문자열 확인 로직 통합
                if "badauth" in response_text.lower():
                    error_message = "API Error: Authentication failed (badauth)."
                elif "notfqdn" in response_text.lower():
                    error_message = "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
                elif "abuse" in response_text.lower():
                    error_message = "API Error: Account blocked for abuse."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if "badauth" in response_text.lower():
                return False, "API Error: Authentication failed (badauth)."
            elif "notfqdn" in response_text.lower():
                return False, "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
            elif "abuse" in response_text.lower():
                return False, "API Error: Account blocked for abuse."
            elif "good" in response_text.lower() or "nochg" in response_text.lower():
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                # Dynu 응답은 "good <new_ip>" 또는 "nochg <current_ip>" 형태일 수 있음.
                # IP 추출 및 비교 로직 추가 권장 (Go 코드는 IP 추출 후 비교함).
                # 여기서는 Go 코드의 단순한 성공 처리(IP 반환)를 따름.
                # 더 정확하게 하려면 _extract_ip_from_response 와 같은 함수 필요.
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
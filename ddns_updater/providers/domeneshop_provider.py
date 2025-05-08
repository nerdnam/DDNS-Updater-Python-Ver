# ddns_updater/providers/domeneshop_provider.py
import requests

from .base_provider import BaseProvider

class DomeneshopProvider(BaseProvider):
    NAME = "domeneshop"
    API_ENDPOINT = "https://api.domeneshop.no/v0/dyndns/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('domeneshop_token')
        self.secret = self.config.get('domeneshop_secret')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.token, self.secret, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (domeneshop_token, domeneshop_secret, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Domeneshop에서 hostname 구성에 필요.
        return ["domeneshop_token", "domeneshop_secret", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Domeneshop API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Domeneshop (Norway) using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Domeneshop은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
        }

        auth = (self.token, self.secret) # HTTP Basic Authentication (username=token, password=secret)
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, auth=auth, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else "" # 오류 시 본문 내용 로깅용
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # HTTP 상태 코드 기반 처리
            if response.status_code == 204: # No Content - 성공
                success_message = f"Successfully updated {hostname_for_query} to {ip_address} (assumed, API status 204 No Content)."
                self.logger.info(success_message)
                return True, success_message
            elif response.status_code == 404: # Not Found
                error_message = f"API Error: Hostname '{hostname_for_query}' not found (HTTP 404)."
                if response_text:
                    error_message += f" Response: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message
            # Domeneshop API는 401 Unauthorized (잘못된 토큰/시크릿), 400 Bad Request (잘못된 파라미터) 등도 반환할 수 있음.
            # response.raise_for_status()를 사용하면 4xx, 5xx 오류 시 예외를 발생시키므로,
            # 좀 더 일반적인 오류 처리를 할 수도 있음.
            # 여기서는 Go 코드의 명시적 상태 코드 처리를 따름.
            else: # 그 외 다른 오류 상태 코드
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
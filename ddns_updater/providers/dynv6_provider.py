# ddns_updater/providers/dynv6_provider.py
import requests

from .base_provider import BaseProvider

class Dynv6Provider(BaseProvider):
    NAME = "dynv6"
    API_PATH = "/api/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('dynv6_token')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.token, self.domain]): # owner는 선택적일 수 있음 (zone 구성에 사용)
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dynv6_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 DynV6에서 zone 구성에 필요.
        return ["dynv6_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # DynV6 API가 TTL 설정을 지원하는지 확인 필요 (일반적으로 DynDNS 계열은 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on DynV6 (free dynamic DNS for IPv6 and IPv4)."

    def _build_zone_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 'zone' 파라미터 값 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        zone_for_query = self._build_zone_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update zone '{zone_for_query}' (record type {record_type}) to IP: {ip_address}")

        api_host = "dynv6.com"
        params = {
            'token': self.token,
            'zone': zone_for_query,
        }

        if record_type == "AAAA": # IPv6
            api_host = f"ipv6.{api_host}"
            params['ipv6'] = ip_address
        else: # IPv4 (기본)
            api_host = f"ipv4.{api_host}"
            params['ipv4'] = ip_address
        
        target_url = f"https://{api_host}{self.API_PATH}"
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # DynV6 API는 성공 시 상태 코드 200을 반환하고, 본문은 "addresses updated" 또는 "no update necessary" 등.
            # Go 코드는 상태 코드 200이면 본문 내용과 관계없이 성공으로 간주.
            if response.status_code == 200:
                success_message = f"Successfully updated zone '{zone_for_query}' to IP {ip_address} (assumed, API status 200)."
                if response_text: # 응답 본문이 있다면 로그에 포함
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            else:
                # HTTP 오류 발생
                error_message = f"API Error: HTTP {response.status_code}"
                # DynV6 오류 응답은 보통 "error: <message>" 또는 "invalid token" 등.
                if response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
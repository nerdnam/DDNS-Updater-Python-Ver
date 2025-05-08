# ddns_updater/providers/ddnss_provider.py
import requests

from .base_provider import BaseProvider

class DdnssProvider(BaseProvider):
    NAME = "ddnss"
    API_ENDPOINT = "https://www.ddnss.de/upd.php"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('ddnss_username')
        self.password = self.config.get('ddnss_password')
        
        # dual_stack: 설정 파일에서 문자열 "true"/"false" 또는 불리언 값으로 올 수 있음
        dual_stack_config = self.config.get('ddnss_dual_stack', False) # 기본값 False
        if isinstance(dual_stack_config, str):
            self.dual_stack = dual_stack_config.lower() == 'true'
        else:
            self.dual_stack = bool(dual_stack_config)
            
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (ddnss_username, ddnss_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        return ["ddnss_username", "ddnss_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"ddnss_dual_stack": False, "ttl": None} # DDNSS.de API가 TTL 설정을 지원하는지 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on DDNSS.de using their DynDNS API."

    def _build_hostname(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname = self._build_hostname()
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname} (record type {record_type}) to IP: {ip_address}")

        params = {
            'user': self.username,
            'pwd': self.password,
            'host': hostname,
        }

        ip_key = "ip" # 기본값
        if self.dual_stack and record_type == "AAAA": # IPv6이고 dual_stack 활성화
            ip_key = "ip6"
        
        params[ip_key] = ip_address

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 오류 원인이 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                # Go 코드의 오류 문자열 확인 로직을 여기에 통합 가능
                if "badysys" in response_text.lower():
                    error_message = "API Error: Invalid system parameter (badysys)."
                elif "badauth" in response_text.lower():
                    error_message = "API Error: Authentication failed (badauth)."
                elif "notfqdn" in response_text.lower():
                    error_message = "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석
            if "badysys" in response_text.lower():
                self.logger.error("API Error: Invalid system parameter (badysys).")
                return False, "API Error: Invalid system parameter (badysys)."
            elif "badauth" in response_text.lower():
                self.logger.error("API Error: Authentication failed (badauth).")
                return False, "API Error: Authentication failed (badauth)."
            elif "notfqdn" in response_text.lower():
                self.logger.error("API Error: Hostname is not a FQDN or does not exist (notfqdn).")
                return False, "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
            elif "updated 1 hostname" in response_text.lower():
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                success_message = f"Successfully updated {hostname} to {ip_address} (assumed)."
                if response_text: # 응답 본문이 있다면 로그에 포함
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            else:
                # 알 수 없는 성공 또는 실패 응답
                error_message = f"API Error: Unknown response from server: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
# ddns_updater/providers/dd24_provider.py
import requests

from .base_provider import BaseProvider

class Dd24Provider(BaseProvider):
    NAME = "dd24"
    API_ENDPOINT = "https://dynamicdns.key-systems.net/update.php"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.password = self.config.get('dd24_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.password, self.domain]): # owner는 선택적일 수 있음 (BuildDomainName에서 처리)
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dd24_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 DD24에서 hostname 구성에 필요. BaseProvider에서 기본값 '@' 처리.
        return ["dd24_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"ttl": None} # DD24 API가 TTL 설정을 지원하는지 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on DomainDiscount24 (DD24) using their DynDNS API."

    def _build_hostname(self):
        """Go 코드의 p.BuildDomainName()과 동일한 역할"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # DD24는 IPv4/IPv6 구분 없이 'ip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname = self._build_hostname()
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname} (record type {record_type}) to IP: {ip_address}")

        params = {
            'hostname': hostname,
            'password': self.password,
            'ip': ip_address
        }

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 오류 원인이 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                if "authorization failed" in response_text.lower():
                    error_message = "API Error: Authentication failed (authorization failed)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석
            if "authorization failed" in response_text.lower():
                self.logger.error("API Error: Authentication failed (authorization failed).")
                return False, "API Error: Authentication failed (authorization failed)."
            elif response_text == "" or "success" in response_text.lower():
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                success_message = f"Successfully updated {hostname} to {ip_address} (assumed)."
                if response_text: # 응답 본문이 있다면 로그에 포함
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            # TODO: Go 코드의 "TODO missing cases" 주석 참고하여,
            # DD24 API 문서에서 다른 오류 응답 문자열이 있는지 확인하고 추가.
            # 예: "hostname not found", "ip address invalid" 등
            else:
                # 알 수 없는 성공 또는 실패 응답
                error_message = f"API Error: Unknown response from server: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
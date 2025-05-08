# ddns_updater/providers/myaddr_provider.py
import requests
from urllib.parse import urlencode # for x-www-form-urlencoded

from .base_provider import BaseProvider

class MyaddrProvider(BaseProvider):
    NAME = "myaddr"
    API_ENDPOINT = "https://myaddr.tools/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('myaddr_api_key')
        # self.domain, self.owner 는 BaseProvider 에서 처리되지만,
        # MyAddr.tools는 키에 호스트 정보가 연결되어 있어 domain/owner 설정이 API 호출에 직접 사용되지 않을 수 있음.
        # 다만, 로깅이나 사용자 식별용으로는 여전히 유용.

        # 필수 설정값 확인
        if not self.api_key: # domain은 BaseProvider에서 이미 확인됨
            error_msg = f"{self.NAME.capitalize()} provider: 'myaddr_api_key' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not self.config.get('domain'):
             self.logger.warning(f"{self.NAME.capitalize()} provider: 'domain' setting is present but might not be directly used in API calls if the API key is tied to a specific host.")


    @staticmethod
    def get_required_config_fields():
        # MyAddr.tools는 API 키가 핵심. domain/owner는 사용자 식별 및 로깅용.
        return ["myaddr_api_key", "domain"] # owner는 선택적으로 간주 가능

    @staticmethod
    def get_optional_config_fields():
        # MyAddr.tools API가 TTL 설정을 지원하는지 확인 필요. owner도 API 호출에는 불필요할 수 있음.
        return {"owner": "@", "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on MyAddr.tools using their API."

    def update_record(self, ip_address, record_type="A", proxied=None):
        # MyAddr.tools는 IP 버전에 따라 API 엔드포인트나 파라미터가 변경되지 않음.
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        # IP 주소 자체도 API 요청 파라미터로 전달.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        # MyAddr.tools는 토큰에 업데이트할 호스트 정보가 연결되어 있음.
        # domain/owner 설정은 주로 로깅 및 사용자 식별용.
        log_hostname = f"{self.config.get('owner', '@')}.{self.config.get('domain')}"
        if self.config.get('owner', '@') == '@':
            log_hostname = self.config.get('domain')
            
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update record associated with API key (for {log_hostname}, record type {record_type}) to IP: {ip_address}")

        payload = {
            'key': self.api_key,
            'ip': ip_address
        }
        # 페이로드를 x-www-form-urlencoded 문자열로 인코딩
        encoded_payload = urlencode(payload)

        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/x-www-form-urlencoded'
            # Accept 헤더는 필수는 아니지만, 명시적으로 text/plain 등을 기대할 수 있음
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.post(self.API_ENDPOINT, data=encoded_payload, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # HTTP 상태 코드 기반 처리 (Go 코드 참조)
            if response.status_code == 200:
                # MyAddr.tools 성공 응답은 보통 간단한 텍스트 (예: "OK", "IP updated")
                # Go 코드는 상태 코드 200이면 본문 내용과 관계없이 성공으로 간주.
                success_message = f"Successfully updated record associated with API key (for {log_hostname}) to IP {ip_address} (assumed, API status 200 OK)."
                if response_text: # 응답 본문이 있다면 로그에 포함
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            elif response.status_code == 400: # Bad Request
                error_message = f"API Error: Bad Request (HTTP 400)."
                if response_text: error_message += f" Response: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message
            elif response.status_code == 404: # Not Found (잘못된 키)
                error_message = f"API Error: Invalid API Key or record not found (HTTP 404)."
                if response_text: error_message += f" Response: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message
            else: # 그 외 다른 오류 상태 코드
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text: error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
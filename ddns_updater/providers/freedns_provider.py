# ddns_updater/providers/freedns_provider.py
import requests

from .base_provider import BaseProvider

class FreednsProvider(BaseProvider):
    NAME = "freedns"
    # API_HOST_IPV4 = "sync.afraid.org" # update_record에서 동적으로 구성
    # API_HOST_IPV6 = "v6.sync.afraid.org"
    # API_PATH_TEMPLATE = "/u/{token}/" # update_record에서 동적으로 구성

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('freedns_token')
        # self.domain, self.owner 는 BaseProvider 에서 처리되지만,
        # FreeDNS는 토큰에 호스트 정보가 연결되어 있어 domain/owner 설정이 API 호출에 직접 사용되지 않을 수 있음.
        # 다만, 로깅이나 사용자 식별용으로는 여전히 유용.

        # 필수 설정값 확인
        if not self.token: # domain은 BaseProvider에서 이미 확인됨
            error_msg = f"{self.NAME.capitalize()} provider: 'freedns_token' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # FreeDNS는 토큰에 업데이트할 호스트 정보가 연결되어 있으므로,
        # domain/owner 설정은 API 호출에 직접 사용되지 않을 수 있지만,
        # 사용자가 어떤 레코드를 업데이트하는지 식별하기 위해 설정 파일에는 필요할 수 있음.
        if not self.config.get('domain'):
             self.logger.warning(f"{self.NAME.capitalize()} provider: 'domain' setting is present but might not be directly used in API calls if the token is tied to a specific host.")


    @staticmethod
    def get_required_config_fields():
        # FreeDNS는 토큰이 핵심. domain/owner는 사용자 식별 및 로깅용.
        return ["freedns_token", "domain"] # owner는 선택적으로 간주 가능

    @staticmethod
    def get_optional_config_fields():
        # FreeDNS API는 TTL 설정을 지원하지 않음. owner도 API 호출에는 불필요할 수 있음.
        return {"owner": "@", "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on FreeDNS (afraid.org) using their update API."

    def update_record(self, ip_address, record_type="A", proxied=None):
        # FreeDNS는 IP 버전에 따라 API 호스트가 변경됨.
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않지만, 호스트 결정에 사용.
        # IP 주소 자체도 API 요청 파라미터로 전달되지 않고, 서버가 요청 IP를 자동 감지.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        api_host_prefix = ""
        if record_type == "AAAA": # IPv6
            api_host_prefix = "v6."
        
        # FreeDNS는 토큰에 업데이트할 호스트 정보가 연결되어 있음.
        # domain/owner 설정은 주로 로깅 및 사용자 식별용.
        # API 호출 시에는 토큰만 경로에 포함.
        log_hostname = f"{self.config.get('owner', '@')}.{self.config.get('domain')}"
        if self.config.get('owner', '@') == '@':
            log_hostname = self.config.get('domain')

        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update record associated with token (for {log_hostname}, record type {record_type}) using detected IP: {ip_address}")

        target_url = f"https://{api_host_prefix}sync.afraid.org/u/{self.token}/"
        
        # FreeDNS는 쿼리 파라미터로 IP나 호스트명을 받지 않음.
        # 서버가 요청 IP를 자동 감지하고, 토큰에 연결된 호스트를 업데이트.
        params = {} 

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if not response_text: # 빈 응답
                return False, "API Error: Received empty response from server."
            
            # FreeDNS 응답은 보통 "Updated <IP> to <hostname>" 또는 "No IP change detected for <hostname>"
            # 또는 오류 메시지.
            # Go 코드는 "no ip change detected" 또는 "updated "로 시작하면 성공으로 간주.
            if "no ip change detected" in response_text.lower() or response_text.lower().startswith("updated "):
                # 성공. 요청한 IP로 업데이트되었다고 가정 (서버가 자동 감지한 IP 사용).
                # API 응답에 실제 업데이트된 IP가 포함될 수 있으므로, 추출하여 비교하는 것이 더 좋음.
                # 여기서는 Go 코드의 단순함을 따라, 성공 응답이면 요청 IP로 업데이트되었다고 가정.
                success_message = f"Successfully updated record associated with token (for {log_hostname})."
                if response_text:
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            # FreeDNS는 "ERROR: <message>" 형태의 오류도 반환할 수 있음.
            elif response_text.lower().startswith("error:"):
                 error_message = f"API Error: {response_text}"
                 self.logger.error(error_message)
                 return False, error_message
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
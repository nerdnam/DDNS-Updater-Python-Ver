# ddns_updater/providers/spdyn_provider.py
import requests
from urllib.parse import quote # 쿼리 파라미터 인코딩은 requests가 자동으로 하지만, 명시적 사용 가능

from .base_provider import BaseProvider

class SpdynProvider(BaseProvider):
    NAME = "spdyn"
    API_ENDPOINT = "https://update.spdyn.de/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('spdyn_username')
        self.password = self.config.get('spdyn_password')
        self.token = self.config.get('spdyn_token')
        
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 및 인증 정보 확인
        if not self.domain: # domain은 BaseProvider에서 처리되지만, 여기서도 명시적 확인 가능
            error_msg = f"{self.NAME.capitalize()} provider: 'domain' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        if not self.token: # 토큰이 없으면 username/password 필수
            if not self.username:
                error_msg = f"{self.NAME.capitalize()} provider: 'spdyn_username' is required if 'spdyn_token' is not set."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
            if not self.password:
                error_msg = f"{self.NAME.capitalize()} provider: 'spdyn_password' is required if 'spdyn_token' is not set."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
        # 토큰이 있으면 username/password는 사용되지 않음.


    @staticmethod
    def get_required_config_fields():
        # owner는 Spdyn에서 hostname 구성에 필요.
        # 인증 정보는 (token) 또는 (username + password) 조합. __init__에서 상세 검증.
        return ["domain", "owner"] 

    @staticmethod
    def get_optional_config_fields():
        # Spdyn API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {
            "spdyn_username": None, 
            "spdyn_password": None, 
            "spdyn_token": None,
            "ttl": None
        } 

    @staticmethod
    def get_description():
        return "Updates DNS records on Spdyn (Securepoint DynDNS) using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Spdyn은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
        }
        
        # 인증 파라미터 설정
        if self.token:
            params['user'] = hostname_for_query # 토큰 사용 시 user는 hostname
            params['pass'] = self.token
        else: # 사용자 이름/비밀번호 사용
            params['user'] = self.username
            params['pass'] = self.password
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # Spdyn은 HTTP Basic Auth를 사용하지 않고, user/pass를 쿼리 파라미터로 전달.
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                # 특정 오류 문자열 확인 (Go 코드 참조)
                if response_text.lower() in ["abuse", "numhost"]:
                    error_message = "API Error: Account blocked for abuse or too many hosts."
                elif response_text.lower() in ["badauth", "!yours"]:
                     error_message = "API Error: Authentication failed."
                elif response_text == "notfqdn": # 대소문자 구분 가능성
                     error_message = "API Error: Hostname is not a FQDN."
                elif response_text.lower() in ["nohost", "fatal"]:
                     error_message = f"API Error: Hostname '{hostname_for_query}' not found or fatal error."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if response_text.lower() in ["abuse", "numhost"]:
                return False, "API Error: Account blocked for abuse or too many hosts."
            elif response_text.lower() in ["badauth", "!yours"]:
                return False, "API Error: Authentication failed."
            elif response_text.lower().startswith("good") or response_text.lower().startswith("nochg"):
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                # Spdyn 응답은 "good <IP Address>" 또는 "nochg <IP Address>" 형태일 수 있음.
                # IP 추출 및 비교 로직 추가 권장.
                # 여기서는 Go 코드의 단순한 성공 처리(IP 반환)를 따름.
                success_message = f"Successfully updated {hostname_for_query} to {ip_address} (assumed)."
                if response_text:
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            elif response_text == "notfqdn": # 대소문자 구분 가능성
                return False, "API Error: Hostname is not a FQDN."
            elif response_text.lower() in ["nohost", "fatal"]:
                return False, f"API Error: Hostname '{hostname_for_query}' not found or fatal error."
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
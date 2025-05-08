# ddns_updater/providers/opendns_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class OpendnsProvider(BaseProvider):
    NAME = "opendns"
    API_HOST = "updates.opendns.com"
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('opendns_username')
        self.password = self.config.get('opendns_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (opendns_username, opendns_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 OpenDNS에서 hostname 구성에 필요.
        return ["opendns_username", "opendns_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # OpenDNS API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on OpenDNS (Cisco Umbrella) using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # OpenDNS는 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않지만, IP 추출 시 사용될 수 있음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<password>@updates.opendns.com/nic/update
        userinfo_user = quote(self.username, safe='')
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
                # OpenDNS는 DynDNS 표준 오류 코드(badauth, nohost 등)를 반환할 수 있음.
                # Go 코드는 상태 코드 200이 아니면 바로 오류 처리.
                # 좀 더 상세한 오류를 위해 response_text를 포함.
                if "badauth" in response_text.lower(): # 예시
                    error_message = "API Error: Authentication failed (badauth)."
                elif "nohost" in response_text.lower(): # 예시
                     error_message = f"API Error: Hostname '{hostname_for_query}' not found (nohost)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if response_text.lower().startswith("good "): # 공백 주의
                # 성공. 응답에서 IP를 추출하여 확인.
                # 예: "good 1.2.3.4"
                ip_string_from_response = response_text[len("good "):].strip()
                extracted_ip = self._extract_ip_from_string(ip_string_from_response, record_type)

                if extracted_ip and extracted_ip == ip_address:
                    msg = f"Successfully updated {hostname_for_query} to {ip_address}. API Response: '{response_text}'"
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    msg = f"Update reported success ('{response_text}'), but API returned IP {extracted_ip} instead of {ip_address}."
                    self.logger.error(msg)
                    return False, msg # IP 불일치 시 실패로 처리
                else: # IP 추출 실패
                    msg = f"Update reported success ('{response_text}'), but could not extract IP from response part: '{ip_string_from_response}'"
                    self.logger.warning(msg)
                    return False, msg # IP 확인 불가 시 실패로 처리
            # OpenDNS는 "nochg" 응답도 성공으로 간주할 수 있음 (DynDNS 표준)
            # Go 코드에는 명시적으로 없지만, 추가 고려 가능.
            # elif response_text.lower().startswith("nochg "):
            #    ... (good과 유사한 IP 추출 및 비교 로직) ...
            else:
                # DynDNS 표준 오류 코드 (badauth, nohost 등)는 보통 HTTP 상태 코드가 200이 아님.
                # 따라서 200인데 "good "로 시작하지 않으면 알 수 없는 응답.
                return False, f"API Error: Unknown success response (200 OK): '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_string(self, ip_string, record_type):
        """주어진 문자열에서 IP 주소를 추출합니다."""
        # OpenDNS 응답은 "good <IP>" 형태이므로, ip_string은 <IP> 부분.
        ip_pattern_str = r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$' # IPv4
        if record_type == "AAAA":
            ip_pattern_str = r'^([0-9A-Fa-f:]+)$' # 매우 기본적인 IPv6 패턴
        
        match = re.match(ip_pattern_str, ip_string, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
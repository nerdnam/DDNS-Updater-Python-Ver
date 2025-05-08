# ddns_updater/providers/infomaniak_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class InfomaniakProvider(BaseProvider):
    NAME = "infomaniak"
    # API 호스트는 Infomaniak 공식 문서에서 확인 필요. Go 코드는 'infomaniak.com' 사용.
    # 일반적인 DynDNS 서비스는 'updates.provider.com' 또는 'dyndns.provider.com' 형태를 많이 사용.
    API_HOST = "infomaniak.com" 
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('infomaniak_username')
        self.password = self.config.get('infomaniak_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (infomaniak_username, infomaniak_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Infomaniak에서 hostname 구성에 필요.
        return ["infomaniak_username", "infomaniak_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Infomaniak API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Infomaniak using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Infomaniak은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않지만, IP 추출 시 사용될 수 있음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<password>@infomaniak.com/nic/update
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

            # HTTP 상태 코드 기반 처리 (Go 코드 참조)
            if response.status_code == 200:
                success_prefixes = ["successfully_changed", "no_change", "good", "nochg"]
                prefix_found = None
                for prefix in success_prefixes:
                    if response_text.lower().startswith(prefix):
                        prefix_found = prefix
                        break
                
                if prefix_found:
                    # 성공. 응답에서 IP를 추출하여 확인.
                    # 예: "successfully_changed 1.2.3.4"
                    ip_string_from_response = response_text[len(prefix_found):].strip()
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
                else:
                    return False, f"API Error: Unknown success response (200 OK): '{response_text}'"

            elif response.status_code == 400: # Bad Request
                if "nohost" in response_text.lower():
                    return False, "API Error: Hostname not found (nohost)."
                elif "badauth" in response_text.lower():
                    return False, "API Error: Authentication failed (badauth)."
                else:
                    error_message = f"API Error: HTTP 400 Bad Request"
                    if response_text: error_message += f" - {response_text}"
                    return False, error_message
            else: # 그 외 다른 오류 상태 코드
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text: error_message += f" - {response_text}"
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_string(self, ip_string, record_type):
        """주어진 문자열에서 IP 주소를 추출합니다."""
        # Infomaniak 응답은 "prefix <IP>" 형태이므로, ip_string은 <IP> 부분.
        # 간단한 IP 형식 검사 및 반환.
        ip_pattern_str = r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$' # IPv4
        if record_type == "AAAA":
            ip_pattern_str = r'^([0-9A-Fa-f:]+)$' # 매우 기본적인 IPv6 패턴
            # 더 견고한 IPv6 정규식 사용 권장
            # 예: ip_pattern_str = r'\b(?:[A-F0-9]{1,4}:){2,7}(?:[A-F0-9]{1,4})\b'
        
        match = re.match(ip_pattern_str, ip_string, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
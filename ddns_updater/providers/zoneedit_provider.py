# ddns_updater/providers/zoneedit_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/토큰 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class ZoneeditProvider(BaseProvider):
    NAME = "zoneedit"
    # API 호스트는 ZoneEdit 공식 문서에서 확인 필요. Go 코드는 'api.cp.zoneedit.com' 사용.
    # 일반적인 DynDNS 서비스는 'dynamic.zoneedit.com' 또는 유사한 형태를 많이 사용.
    API_HOST = "api.cp.zoneedit.com" 
    API_PATH = "/dyn/generic.php" # 또는 /dyndns/update.php 등

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('zoneedit_username')
        self.token = self.config.get('zoneedit_token') # ZoneEdit은 토큰을 비밀번호처럼 사용
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (zoneedit_username, zoneedit_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # ZoneEdit은 owner='*'를 wildcard 파라미터로 처리하므로, owner 자체에 대한 와일드카드 금지는 불필요할 수 있음.
        # Go 코드는 owner='*'를 금지. 여기서는 일단 따름.
        if self.config.get('owner') == '*':
            self.logger.warning(f"{self.NAME.capitalize()}: Wildcard owner ('*') is set. This will be used for the 'wildcard=ON' parameter if applicable, not as part of the hostname itself for ZoneEdit's DynDNS.")
            # error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') should be handled via 'wildcard=ON' parameter, not in owner field."
            # self.logger.error(error_msg)
            # raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 ZoneEdit에서 hostname 구성에 필요.
        return ["zoneedit_username", "zoneedit_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # ZoneEdit API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on ZoneEdit using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # ZoneEdit은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않지만, IP 추출 시 사용될 수 있음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<token>@<API_HOST>/<API_PATH>
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.token, safe='') # ZoneEdit은 토큰을 비밀번호처럼 사용
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
        }
        
        owner_val = self.config.get('owner', '@')
        if owner_val == '*':
            params['wildcard'] = 'ON' # Go 코드 참조

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                # ZoneEdit 오류는 응답 본문에 포함될 수 있음
                if 'error code="708"' in response_text.lower() or "failed login" in response_text.lower():
                    error_message = f"API Error: Authentication failed (user: {self.username})."
                elif 'error code="709"' in response_text.lower() or "invalid hostname" in response_text.lower():
                    error_message = f"API Error: Invalid hostname '{hostname_for_query}'."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if not response_text: # 빈 응답
                return False, "API Error: Received empty response from server."
            
            response_lower = response_text.lower()
            if 'success_code="200"' in response_lower: # 성공 코드 확인
                # 성공. 응답에서 IP를 추출하여 확인.
                # ZoneEdit 응답 형식: <SUCCESS CODE="200" IP="1.2.3.4" HOSTNAME="host.example.com">
                extracted_ip = self._extract_ip_from_zoneedit_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    msg = f"Successfully updated {hostname_for_query} to {ip_address}. API Response: '{response_text}'"
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    msg = f"Update reported success ('{response_text}'), but API returned IP {extracted_ip} instead of {ip_address}."
                    self.logger.error(msg)
                    return False, msg # IP 불일치 시 실패로 처리
                else: # IP 추출 실패
                    # Go 코드는 이 경우 (ips 길이가 0) errors.ErrReceivedNoIP 반환.
                    # 하지만 success_code="200"이므로, IP 확인 없이 성공으로 간주할 수도 있음.
                    # 여기서는 IP 확인 실패 시 오류로 처리.
                    msg = f"Update reported success ('{response_text}'), but could not extract IP from response."
                    self.logger.warning(msg)
                    return False, msg
            elif 'error code="702"' in response_lower or "minimum 600 seconds between requests" in response_lower:
                return False, "API Error: Update too soon (minimum 10 minutes between requests)."
            elif 'error code="709"' in response_lower or "invalid hostname" in response_lower:
                return False, f"API Error: Invalid hostname '{hostname_for_query}'."
            elif 'error code="708"' in response_lower or "failed login" in response_lower:
                return False, f"API Error: Authentication failed (user: {self.username})."
            # Go 코드에는 없는 DynDNS 표준 오류 코드 추가 고려 (예: nohost, badauth 등)
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_zoneedit_response(self, response_text, record_type):
        """ZoneEdit 성공 응답 텍스트에서 IP 주소를 추출합니다."""
        # ZoneEdit 응답 예시: <SUCCESS CODE="200" IP="1.2.3.4" HOSTNAME="host.example.com">
        # 또는 <SUCCESS CODE="200" IPV6="2001:db8::1" HOSTNAME="host.example.com">
        ip_attr_name = 'IP'
        if record_type == "AAAA":
            # ZoneEdit이 IPv6에 대해 IPV6="2001:db8::1" 같은 다른 속성명을 사용하는지 확인 필요.
            # 일단은 IP 속성에서 IPv6도 찾도록 시도.
            # ip_attr_name = 'IPV6' # 만약 그렇다면
            pass

        match = re.search(r'{}="([^"]+)"'.format(ip_attr_name), response_text, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # 만약 IPv6에 다른 속성명을 사용한다면, 추가 검색
        if record_type == "AAAA":
            match_ipv6 = re.search(r'IPV6="([^"]+)"', response_text, re.IGNORECASE)
            if match_ipv6:
                return match_ipv6.group(1)
                
        return None
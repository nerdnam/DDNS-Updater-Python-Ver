# ddns_updater/providers/noip_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class NoipProvider(BaseProvider):
    NAME = "noip"
    API_HOST = "dynupdate.no-ip.com"
    API_PATH = "/nic/update"
    MAX_USERNAME_LENGTH = 50

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('noip_username')
        self.password = self.config.get('noip_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 및 형식 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (noip_username, noip_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if len(self.username) > self.MAX_USERNAME_LENGTH:
            error_msg = f"{self.NAME.capitalize()} provider: Username '{self.username}' is longer than maximum {self.MAX_USERNAME_LENGTH} characters."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 No-IP에서 hostname 구성에 필요.
        return ["noip_username", "noip_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # No-IP API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on No-IP using their DynDNS API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # No-IP는 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않지만, IP 추출 시 사용될 수 있음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<password>@dynupdate.no-ip.com/nic/update
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.password, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
            # No-IP는 여러 IP를 콤마로 구분하여 myip에 전달 가능.
            # 이 클라이언트는 단일 IP 업데이트를 가정.
        }
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # Go 코드의 응답 처리 순서 (오류 문자열 우선 확인)
            if not response_text and response.status_code == 200: # 빈 응답인데 성공? (Go는 ErrReceivedNoResult)
                self.logger.warning(f"{self.NAME.capitalize()}: Received empty response with status 200 OK.")
                return False, "API Error: Received empty response with status 200 OK."
            if response_text == "911":
                return False, "API Error: DNS server-side issue (911)."
            if response_text == "abuse":
                return False, "API Error: Account banned due to abuse."
            if response_text == "!donator": # Go 코드에서는 !donator
                return False, "API Error: Feature unavailable (donation required?)."
            if response_text == "badagent":
                return False, "API Error: User-Agent banned."
            if response_text == "badauth":
                return False, "API Error: Authentication failed (badauth)."
            if response_text == "nohost":
                return False, f"API Error: Hostname '{hostname_for_query}' does not exist or is not managed by this account (nohost)."

            # 위 특정 오류 문자열에 해당하지 않으면, 상태 코드 확인
            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text: error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200이고, 특정 오류 문자열도 아닐 때, 성공 응답 확인
            if "nochg" in response_text.lower() or "good" in response_text.lower():
                # 성공. 응답에서 IP를 추출하여 확인.
                extracted_ip = self._extract_ip_from_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    msg = f"Successfully updated {hostname_for_query} to {ip_address}. API Response: '{response_text}'"
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    msg = f"Update reported success ('{response_text}'), but API returned IP {extracted_ip} instead of {ip_address}."
                    self.logger.error(msg)
                    return False, msg # IP 불일치 시 실패로 처리
                else: # IP 추출 실패
                    msg = f"Update reported success ('{response_text}'), but could not extract IP from response."
                    self.logger.warning(msg)
                    return False, msg # IP 확인 불가 시 실패로 처리 (Go 코드와 일치)
            
            return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_response(self, response_text, record_type):
        """응답 텍스트에서 IP 주소를 추출합니다 (Go의 ipextract.IPv4/IPv6 참조)."""
        # No-IP 응답 형식: "good <IP Address>" 또는 "nochg <IP Address>"
        parts = response_text.split()
        if len(parts) > 1:
            potential_ip = parts[-1] # 마지막 부분이 IP일 가능성
            ip_pattern_str = r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$' # IPv4
            if record_type == "AAAA":
                ip_pattern_str = r'^([0-9A-Fa-f:]+)$' # 매우 기본적인 IPv6 패턴
            
            if re.match(ip_pattern_str, potential_ip):
                return potential_ip
        return None
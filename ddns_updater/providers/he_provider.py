# ddns_updater/providers/he_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class HeProvider(BaseProvider):
    NAME = "he"
    API_HOST = "dyn.dns.he.net"
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.password = self.config.get('he_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정 (HE.net은 FQDN을 username으로 사용하므로 owner가 중요)
        if not self.config.get('owner'):
            self.config['owner'] = '@' 
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.password, self.domain]): # owner는 기본값 처리
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (he_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 HE.net에서 FQDN(username) 및 hostname 파라미터 구성에 필요.
        return ["he_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # HE.net API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on HE.net (Hurricane Electric) using their DynDNS API."

    def _build_fqdn(self):
        """API의 Userinfo 및 'hostname' 파라미터에 사용될 FQDN 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # HE.net은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않지만, IP 추출 시 사용될 수 있음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        fqdn = self._build_fqdn()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {fqdn} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<fqdn>:<password>@dyn.dns.he.net/nic/update
        # FQDN/비밀번호에 특수문자가 있을 경우를 대비해 quote 처리.
        userinfo_user = quote(fqdn, safe='')
        userinfo_pass = quote(self.password, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': fqdn, # HE.net은 hostname 파라미터도 요구
            'myip': ip_address
        }
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # Go 코드에서는 빈 응답 + 상태 코드 != 200을 먼저 체크.
            # 여기서는 상태 코드 != 200을 먼저 체크하고, 그 안에서 빈 응답을 고려.
            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                if not response_text: # 빈 응답인데 상태 코드가 200이 아님
                     error_message += " - Received empty response with non-OK status."
                elif "badauth" in response_text.lower(): # 상태 코드가 200이 아니면서 badauth 포함
                     error_message = "API Error: Authentication failed (badauth)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석
            if not response_text and response.status_code == 200: # Go 코드의 "" 케이스 (상태 코드 200인데 빈 응답)
                # 이 경우는 거의 발생하지 않거나, API 문서에 명시된 특정 의미가 있을 수 있음.
                # Go 코드는 errors.ErrReceivedNoResult 반환.
                self.logger.warning(f"{self.NAME.capitalize()}: Received empty response with status 200 OK.")
                return False, "API Error: Received empty response with status 200 OK."

            if "badauth" in response_text.lower(): # 상태 코드 200인데 badauth 포함 (이론적으로는 401이어야 함)
                return False, "API Error: Authentication failed (badauth in 200 OK response)."
            
            if "nochg" in response_text.lower() or "good" in response_text.lower():
                # 성공. 응답에서 IP를 추출하여 확인.
                extracted_ip = self._extract_ip_from_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    msg = f"Successfully updated {fqdn} to {ip_address}. API Response: '{response_text}'"
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    msg = f"Update reported success-like response ('{response_text}'), but API returned IP {extracted_ip} instead of {ip_address}."
                    self.logger.error(msg)
                    return False, msg # IP 불일치 시 실패로 처리
                else: # IP 추출 실패
                    msg = f"Update reported success-like response ('{response_text}'), but could not extract IP from response."
                    self.logger.warning(msg)
                    return False, msg # IP 확인 불가 시 실패로 처리 (Go 코드와 일치)
            
            return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_response(self, response_text, record_type):
        """응답 텍스트에서 IP 주소를 추출합니다 (Go의 ipextract.IPv4/IPv6 참조)."""
        # HE.net 응답 형식: "good <IP Address>" 또는 "nochg <IP Address>"
        parts = response_text.split()
        if len(parts) > 1:
            potential_ip = parts[-1] # 마지막 부분이 IP일 가능성
            # 간단한 IP 형식 검사
            ip_pattern_str = r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$' # IPv4
            if record_type == "AAAA":
                ip_pattern_str = r'^([0-9A-Fa-f:]+)$' # 매우 기본적인 IPv6 패턴
            
            if re.match(ip_pattern_str, potential_ip):
                return potential_ip
        return None
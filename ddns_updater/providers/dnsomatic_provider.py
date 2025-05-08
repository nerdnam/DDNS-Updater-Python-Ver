# ddns_updater/providers/dnsomatic_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class DnsomaticProvider(BaseProvider):
    NAME = "dnsomatic"
    API_HOST = "updates.dnsomatic.com"
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('dnsomatic_username')
        self.password = self.config.get('dnsomatic_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dnsomatic_username, dnsomatic_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 DNS-O-Matic에서 hostname 구성에 필요.
        return ["dnsomatic_username", "dnsomatic_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # DNS-O-Matic은 DynDNS v2 표준을 따르므로 TTL 설정은 일반적으로 지원하지 않음.
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on DNS-O-Matic (which can update multiple other services)."

    @property
    def proxied(self):
        """
        DNS-O-Matic에서 owner가 'all'이면 모든 호스트를 업데이트하는 것을 의미.
        Go 코드에서는 이를 'proxied'와 유사하게 해석.
        """
        return self.config.get('owner', '').lower() == 'all'

    def _build_hostname_for_query(self):
        """쿼리용 호스트명 구성"""
        owner = self.config.get('owner', '@')
        # DNS-O-Matic에서 owner가 'all'이면 hostname은 domain (예: ddnskey.com)
        # owner가 '*'이면 hostname은 domain (Go 코드의 wildcard 처리와 연관)
        # 그 외에는 owner.domain
        if owner.lower() == 'all' or owner == '*':
            return self.domain
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied_param=None):
        # proxied_param은 BaseProvider 시그니처를 따르지만, DNS-O-Matic에서는 자체 proxied 로직(owner=='all') 사용.
        if proxied_param is not None:
             self.logger.debug(f"{self.NAME.capitalize()} provider uses its own logic for 'all' hosts, 'proxied' argument ignored.")

        # DNS-O-Matic은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용.
        # record_type은 API 요청에 직접 사용되지 않지만, IP 추출 시 사용될 수 있음.
        
        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<password>@updates.dnsomatic.com/nic/update
        # 사용자 이름/비밀번호에 특수문자가 있을 경우를 대비해 quote 처리.
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.password, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'myip': ip_address,
            'wildcard': "NOCHG", # 기본값
            'hostname': hostname_for_query,
            'mx': "NOCHG",
            'backmx': "NOCHG"
        }

        # Go 코드의 wildcard 처리 로직 반영
        if self.config.get('owner', '').lower() == '*':
            params['wildcard'] = "ON"
            # hostname은 이미 _build_hostname_for_query에서 domain으로 설정됨

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 오류 원인이 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                # Go 코드의 오류 문자열 확인 로직 통합
                if "nohost" in response_text.lower() or "notfqdn" in response_text.lower():
                    error_message = "API Error: Hostname not found or not a FQDN."
                elif "badauth" in response_text.lower():
                    error_message = "API Error: Authentication failed (badauth)."
                # ... (다른 Go 코드의 오류 케이스들 추가) ...
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if "nohost" in response_text.lower() or "notfqdn" in response_text.lower():
                return False, "API Error: Hostname not found or not a FQDN."
            if "badauth" in response_text.lower():
                return False, "API Error: Authentication failed (badauth)."
            if "badagent" in response_text.lower():
                return False, "API Error: User-Agent banned."
            if "abuse" in response_text.lower():
                return False, "API Error: Account banned due to abuse."
            if "dnserr" in response_text.lower() or "911" in response_text: # 911은 숫자로 비교하지 않도록 주의
                return False, f"API Error: DNS server-side issue ({response_text})."

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
                    # 성공 응답이지만 IP 확인 불가. 일단 성공으로 처리할지 결정 필요.
                    # Go 코드는 IP 추출 실패 시 errors.ErrReceivedNoIP 반환.
                    return False, msg # IP 확인 불가 시 실패로 처리
            
            return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_response(self, response_text, record_type):
        """응답 텍스트에서 IP 주소를 추출합니다 (Go의 ipextract.IPv4/IPv6 참조)."""
        # DNS-O-Matic 응답 형식에 따라 IP 추출 로직 구현 필요.
        # 예: "good 1.2.3.4" 또는 "nochg 1.2.3.4" 형태일 수 있음.
        ip_pattern_str = r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b' # IPv4
        if record_type == "AAAA":
            # 매우 기본적인 IPv6 패턴, 더 견고한 패턴 사용 권장
            ip_pattern_str = r'\b(?:[A-F0-9]{1,4}:){2,7}(?:[A-F0-9]{1,4})\b' 
        
        match = re.search(ip_pattern_str, response_text, re.IGNORECASE)
        if match:
            return match.group(1) # 첫 번째 그룹 (IP 주소 자체)
        return None
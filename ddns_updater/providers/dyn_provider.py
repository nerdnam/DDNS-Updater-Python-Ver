# ddns_updater/providers/dyn_provider.py
import requests
from urllib.parse import quote # URL에 사용자 이름/키 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class DynProvider(BaseProvider):
    NAME = "dyn"
    API_HOST = "members.dyndns.org"
    API_PATH = "/v3/update" # DynDNS API v3

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('dyn_username')
        self.client_key = self.config.get('dyn_client_key')

        # 하위 호환성: password가 있으면 client_key로 사용
        if not self.client_key and self.config.get('dyn_password'):
            self.client_key = self.config.get('dyn_password')
            self.logger.info(f"{self.NAME.capitalize()}: Using 'dyn_password' as 'dyn_client_key' for backward compatibility.")
        
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.username, self.client_key, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dyn_username, dyn_client_key/dyn_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Dyn에서 hostname 구성에 필요.
        # client_key 또는 password (하위 호환) 중 하나 필요.
        return ["dyn_username", "domain", "owner"] # __init__에서 client_key/password 조합 확인

    @staticmethod
    def get_optional_config_fields():
        # Dyn API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        return {"dyn_client_key": None, "dyn_password": None, "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Oracle Dyn using their DynDNS API (v3)."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Dyn은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<clientKey>@members.dyndns.org/v3/update
        # 사용자 이름/키에 특수문자가 있을 경우를 대비해 quote 처리.
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.client_key, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
            # Dyn API v3는 다른 파라미터도 지원할 수 있음 (예: 'offline', 'wildcard')
            # Go 코드는 기본 업데이트만 사용.
        }

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # auth 파라미터를 사용하지 않고 URL에 userinfo를 포함하여 요청
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 오류 원인이 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                # Go 코드의 오류 문자열 확인 로직 통합
                if response_text.lower().startswith("notfqdn"):
                    error_message = "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
                elif response_text.lower().startswith("badrequest"):
                     error_message = "API Error: Bad request."
                # Dyn은 'badauth', 'abuse', 'numhost', 'nohost' 등의 응답도 반환할 수 있음.
                elif "badauth" in response_text.lower():
                     error_message = "API Error: Authentication failed (badauth)."
                elif "abuse" in response_text.lower():
                     error_message = "API Error: Account blocked for abuse."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if response_text.lower().startswith("notfqdn"):
                return False, "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
            elif response_text.lower().startswith("badrequest"):
                return False, "API Error: Bad request."
            elif response_text.lower().startswith("good"):
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                # Dyn 응답은 "good <new_ip>" 또는 "nochg <current_ip>" 형태일 수 있음.
                # IP 추출 및 비교 로직 추가 권장.
                extracted_ip = self._extract_ip_from_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    success_message = f"Successfully updated {hostname_for_query} to {ip_address}."
                    if response_text:
                        success_message += f" API Response: '{response_text}'"
                    self.logger.info(success_message)
                    return True, success_message
                elif extracted_ip: # good인데 IP가 다르면 (nochg의 경우)
                    if "nochg" in response_text.lower() and extracted_ip == ip_address: # nochg인데 IP가 같으면 성공
                         success_message = f"IP address {ip_address} for {hostname_for_query} is already up to date."
                         if response_text:
                              success_message += f" API Response: '{response_text}'"
                         self.logger.info(success_message)
                         return True, success_message
                    # good인데 IP가 다르거나, nochg인데 IP가 다른 경우
                    msg = f"Update reported success-like response ('{response_text}'), but extracted IP ({extracted_ip}) does not match target IP ({ip_address})."
                    self.logger.warning(msg)
                    return False, msg # IP 불일치 또는 확인 불가 시 실패로 처리
                else: # good인데 IP 추출 실패
                    msg = f"Update reported success-like response ('{response_text}'), but could not extract IP."
                    self.logger.warning(msg)
                    return False, msg # IP 확인 불가 시 실패로 처리
            # Dyn API는 'badauth', 'numhost', 'nohost', 'abuse' 등의 응답도 반환.
            # 위에서 HTTP 오류 처리 시 일부 커버 가능.
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_response(self, response_text, record_type):
        """응답 텍스트에서 IP 주소를 추출합니다 (예: "good 1.2.3.4", "nochg 1.2.3.4")."""
        # Dyn 응답은 "good <ip>" 또는 "nochg <ip>" 형태.
        parts = response_text.split()
        if len(parts) > 1:
            # 마지막 부분이 IP 주소일 가능성이 높음.
            potential_ip = parts[-1]
            # 간단한 IP 형식 검사 (더 정확한 정규식 사용 가능)
            ip_pattern_str = r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$' # IPv4
            if record_type == "AAAA":
                ip_pattern_str = r'^([0-9A-Fa-f:]+)$' # 매우 기본적인 IPv6 패턴
            
            if re.match(ip_pattern_str, potential_ip):
                return potential_ip
        return None
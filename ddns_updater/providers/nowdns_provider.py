# ddns_updater/providers/nowdns_provider.py
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class NowdnsProvider(BaseProvider):
    NAME = "nowdns"
    API_HOST = "now-dns.com"
    API_PATH = "/update"

    def __init__(self, config, logger):
        # Now-DNS는 owner 개념 없이 domain에 FQDN을 사용하므로,
        # BaseProvider의 owner를 사용하지 않도록 __init__을 약간 다르게 처리할 수 있으나,
        # 일관성을 위해 BaseProvider를 그대로 사용하고, 내부적으로 owner를 무시하거나 @로 고정.
        # 사용자는 domain에 FQDN (e.g., yourhost.now-dns.org)을 입력해야 함.
        # owner 설정은 무시됨.
        
        # BaseProvider.__init__ 호출 전에 owner를 강제로 @로 설정하거나,
        # BaseProvider가 owner 없이 domain만으로도 초기화될 수 있도록 수정 필요.
        # 여기서는 BaseProvider가 owner를 필수로 가정하지 않는다고 보고,
        # owner 설정은 내부적으로 무시.
        
        # config_copy = config.copy()
        # config_copy['owner'] = '@' # BaseProvider를 위해 임시 owner 설정
        # super().__init__(config_copy, logger)
        # self.domain = config.get('domain') # 원본 domain 사용
        
        # 또는 더 간단하게, BaseProvider의 owner를 사용하되, API 호출 시 무시.
        # 사용자가 owner를 입력해도 API에는 영향 없음.
        super().__init__(config, logger) # domain, owner 초기화
        if self.config.get('owner', '@') != '@':
            self.logger.warning(f"{self.NAME.capitalize()} provider uses the 'domain' field as the full hostname. The 'owner' field ('{self.config.get('owner')}') will be ignored for API calls.")
        
        self.username = self.config.get('nowdns_username')
        self.password = self.config.get('nowdns_password')
        
        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (nowdns_username, nowdns_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # Now-DNS는 domain (FQDN), username, password가 필수. owner는 API에 직접 사용 안 됨.
        return ["nowdns_username", "nowdns_password", "domain"]

    @staticmethod
    def get_optional_config_fields():
        # Now-DNS API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)
        # owner는 API에 사용되지 않으므로 선택 사항에서 제외하거나, 기본값 @로 두되 무시됨을 명시.
        return {"owner": "@", "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Now-DNS.com using their DynDNS API."

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Now-DNS는 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        # 'hostname' 파라미터에는 전체 FQDN (설정의 'domain' 값)을 사용.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        # Now-DNS는 domain 설정이 FQDN이어야 함. owner는 무시.
        hostname_for_query = self.domain 
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<username>:<password>@now-dns.com/update
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
                if "good" in response_text.lower() or "nochg" in response_text.lower():
                    # 성공. 요청한 IP로 업데이트되었다고 가정 (API가 실제 IP를 반환하지 않음).
                    # Go 코드는 요청 IP를 파싱해서 형식 검증 후 반환.
                    # 여기서는 요청 IP를 그대로 성공 메시지에 사용.
                    success_message = f"Successfully updated {hostname_for_query} to {ip_address} (assumed)."
                    if response_text:
                         success_message += f" API Response: '{response_text}'"
                    self.logger.info(success_message)
                    return True, success_message
                else:
                    return False, f"API Error: Unknown success response (200 OK): '{response_text}'"

            elif response.status_code == 400: # Bad Request
                if "nohost" in response_text.lower():
                    return False, f"API Error: Hostname '{hostname_for_query}' not found (nohost)."
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
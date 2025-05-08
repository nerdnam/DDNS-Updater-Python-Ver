# ddns_updater/providers/desec_provider.py
import requests
from urllib.parse import quote # URL에 사용자 이름/토큰 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class DesecProvider(BaseProvider):
    NAME = "desec"
    API_HOST = "update.dedyn.io"
    API_PATH = "/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('desec_token')
        # self.domain 은 BaseProvider 에서 처리
        # self.owner 는 BaseProvider 에서 기본값 '@' 처리, Go 코드처럼 여기서도 명시적 기본값 설정 가능
        if not self.config.get('owner'): # owner가 명시적으로 없으면 '@' 사용
            self.config['owner'] = '@' 
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")


        # 필수 설정값 확인
        if not all([self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (desec_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 deSEC에서 hostname 구성 및 인증 정보(URL userinfo)에 필요.
        return ["desec_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"ttl": None} # deSEC API가 TTL 설정을 지원하는지 확인 필요 (DynDNS v2 표준은 보통 미지원)

    @staticmethod
    def get_description():
        return "Updates DNS records on deSEC.io using their DynDNS API."

    def _build_full_domain_name(self):
        """Go 코드의 p.BuildDomainName()과 동일한 역할"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 쿼리용 호스트명 구성"""
        # deSEC은 hostname 파라미터에 owner.domain 형태를 기대함.
        # owner가 @이면 domain만 전달하는 것이 일반적이나, deSEC 문서를 확인해야 함.
        # Go 코드는 owner가 @여도 owner.domain (즉, @.domain)을 전달하는 것으로 보임.
        # 여기서는 Go 코드의 동작을 따름.
        owner = self.config.get('owner', '@')
        return f"{owner}.{self.domain}"


    def update_record(self, ip_address, record_type="A", proxied=None):
        # deSEC은 IPv4/IPv6 구분 없이 'myip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        full_domain_name = self._build_full_domain_name() # 인증 정보용 (userinfo)
        hostname_for_query = self._build_hostname_for_query() # 'hostname' 쿼리 파라미터용
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {full_domain_name} (record type {record_type}) to IP: {ip_address}")

        # URL 구성: https://<full_domain_name>:<token>@update.dedyn.io/nic/update
        # requests 라이브러리는 URL의 userinfo 부분을 자동으로 HTTP Basic Auth 헤더로 변환해줌.
        # 사용자 이름/토큰에 특수문자가 있을 경우를 대비해 quote 처리.
        # (주의: 토큰에 ':'가 포함되면 문제가 될 수 있으므로, deSEC 토큰 형식 확인 필요)
        userinfo_user = quote(full_domain_name, safe='')
        userinfo_pass = quote(self.token, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.API_HOST}{self.API_PATH}"
        
        params = {
            'hostname': hostname_for_query,
            'myip': ip_address
        }

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # auth 파라미터를 사용하지 않고 URL에 userinfo를 포함하여 요청
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # HTTP 상태 코드 우선 처리
            if response.status_code == 401:
                self.logger.error(f"API Error: Authentication failed (HTTP 401). Response: '{response_text}'")
                return False, f"API Error: Authentication failed (HTTP 401). Response: '{response_text}'"
            elif response.status_code == 404:
                self.logger.error(f"API Error: Hostname not found (HTTP 404). Response: '{response_text}'")
                return False, f"API Error: Hostname not found (HTTP 404). Response: '{response_text}'"
            elif response.status_code != 200:
                self.logger.error(f"API Error: HTTP {response.status_code} - {response_text}")
                return False, f"API Error: HTTP {response.status_code} - {response_text}"

            # 상태 코드 200일 때 응답 본문 분석
            if response_text.lower().startswith("notfqdn"):
                self.logger.error("API Error: Hostname is not a FQDN or does not exist (notfqdn).")
                return False, "API Error: Hostname is not a FQDN or does not exist (notfqdn)."
            elif response_text.lower().startswith("badrequest"):
                self.logger.error("API Error: Bad request.")
                return False, "API Error: Bad request."
            elif response_text.lower().startswith("good"):
                # 성공. 요청한 IP로 업데이트되었다고 가정.
                success_message = f"Successfully updated {full_domain_name} to {ip_address} (assumed)."
                if response_text: # 응답 본문이 있다면 로그에 포함
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            # deSEC API는 "good <ip>" 또는 "nochg <ip>" 형태로 응답할 수도 있음.
            # "good"만 확인하는 것은 Go 코드와 동일.
            # 더 정확하게 하려면 응답에서 IP를 추출하여 비교하는 로직 추가 가능.
            else:
                # 알 수 없는 성공 또는 실패 응답
                error_message = f"API Error: Unknown response from server: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
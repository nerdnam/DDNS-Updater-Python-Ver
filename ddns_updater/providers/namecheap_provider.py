# ddns_updater/providers/namecheap_provider.py
import re
import requests
import xml.etree.ElementTree as ET # XML 파싱

from .base_provider import BaseProvider

class NamecheapProvider(BaseProvider):
    NAME = "namecheap"
    API_ENDPOINT = "https://dynamicdns.park-your-domain.com/update"
    # Namecheap DDNS Password는 32자리 16진수 문자열
    PASSWORD_REGEX = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.ddns_password = self.config.get('namecheap_ddns_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' # Namecheap은 host 파라미터에 @ 또는 서브도메인 사용
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 및 형식 확인
        if not all([self.ddns_password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (namecheap_ddns_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not self.PASSWORD_REGEX.match(self.ddns_password):
            error_msg = f"{self.NAME.capitalize()} provider: 'namecheap_ddns_password' format is invalid (must be 32 hex characters)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Namecheap DDNS는 IPv4만 지원 (Go 코드 기준)
        ip_version_setting = self.config.get('ip_version', 'ipv4').lower()
        if ip_version_setting != 'ipv4':
            self.logger.warning(f"{self.NAME.capitalize()} provider only supports IPv4. Configured ip_version '{ip_version_setting}' will be ignored for API calls.")


    @staticmethod
    def get_required_config_fields():
        # owner는 Namecheap에서 host 파라미터에 사용됨.
        return ["namecheap_ddns_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Namecheap DDNS API는 TTL 설정을 지원하지 않는 것으로 보임.
        # ip_version은 내부적으로 IPv4로 고정.
        return {"ip_version": "ipv4", "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Namecheap using their Dynamic DNS API (IPv4 only)."

    def update_record(self, ip_address, record_type="A", proxied=None):
        # Namecheap DDNS는 IPv4만 지원하므로, record_type은 항상 'A'여야 함.
        # ip_address도 IPv4여야 함.
        if record_type != "A":
            self.logger.warning(f"{self.NAME.capitalize()} provider only supports A records (IPv4). Requested type {record_type} ignored.")
            # 또는 여기서 오류를 반환할 수도 있음:
            # return False, f"Namecheap only supports A records (IPv4), requested {record_type}."

        # TODO: ip_address가 IPv4인지 확인하는 로직 추가 (예: ipaddress 라이브러리 사용)
        # from ipaddress import ip_address as ipaddr_obj, AddressValueError
        # try:
        #     if ipaddr_obj(ip_address).version != 4:
        #         return False, f"Namecheap only supports IPv4 addresses. Provided IP: {ip_address}"
        # except AddressValueError:
        #     return False, f"Invalid IP address format: {ip_address}"


        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update host '{owner_val}' for domain '{self.domain}' to IP: {ip_address}")

        params = {
            'host': owner_val,
            'domain': self.domain,
            'password': self.ddns_password,
            'ip': ip_address # IPv4 주소
        }
        
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/xml' # Namecheap API는 XML 응답
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                # Namecheap 오류는 XML 내 <errors><Err1>...</Err1></errors> 또는 단순 텍스트일 수 있음
                try:
                    root = ET.fromstring(response_text)
                    err_element = root.find(".//errors/Err1") # XPath-like find
                    if err_element is not None and err_element.text:
                        error_message += f" - API Error: {err_element.text.strip()}"
                    elif response_text:
                         error_message += f" - {response_text}"
                except ET.ParseError:
                    if response_text:
                        error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 XML 응답 본문 분석
            try:
                root = ET.fromstring(response_text)
                
                # 오류 확인: <errors><Err1>Error message</Err1></errors>
                err_element = root.find(".//errors/Err1") # 좀 더 구체적인 경로 사용 가능
                if err_element is not None and err_element.text and err_element.text.strip():
                    api_error_msg = err_element.text.strip()
                    self.logger.error(f"API Error from Namecheap: {api_error_msg}")
                    return False, f"API Error from Namecheap: {api_error_msg}"

                # 성공 시 IP 확인: <IP>1.2.3.4</IP>
                ip_element = root.find(".//IP") # 좀 더 구체적인 경로 사용 가능
                if ip_element is not None and ip_element.text:
                    returned_ip = ip_element.text.strip()
                    if returned_ip == ip_address:
                        success_message = f"Successfully updated host '{owner_val}' for domain '{self.domain}' to IP {ip_address}."
                        if response_text:
                             success_message += f" API Response: '{response_text}'" # 전체 XML 로깅
                        self.logger.info(success_message)
                        return True, success_message
                    else:
                        msg = f"Update reported success, but API returned IP {returned_ip} instead of {ip_address}. Response: '{response_text}'"
                        self.logger.error(msg)
                        return False, msg # IP 불일치 시 실패로 처리
                else:
                    # Go 코드는 IP 필드가 없으면 요청 IP로 성공 간주.
                    # 이는 "nochg"와 유사한 상황일 수 있음. API 문서 확인 필요.
                    self.logger.info(f"Successfully updated (assumed, no IP in XML response) host '{owner_val}' for domain '{self.domain}' to IP {ip_address}. API Response: '{response_text}'")
                    return True, f"Successfully updated (assumed, no IP in XML response). API Response: '{response_text}'"

            except ET.ParseError:
                return False, f"API Error: Failed to parse XML response: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
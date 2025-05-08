# ddns_updater/providers/duckdns_provider.py
import re
import requests

from .base_provider import BaseProvider

class DuckdnsProvider(BaseProvider):
    NAME = "duckdns"
    API_ENDPOINT = "https://www.duckdns.org/update"
    # DuckDNS 토큰은 UUID 형식: 8-4-4-4-12 자리 16진수 문자열
    TOKEN_REGEX = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.IGNORECASE)
    ETLD = "duckdns.org"

    def __init__(self, config, logger):
        super().__init__(config, logger) # domain, owner 초기화
        self.token = self.config.get('duckdns_token')
        
        # DuckDNS의 domain/owner 처리 (Go 코드 로직 반영)
        # 설정 파일의 domain은 'yoursubdomain' 또는 'yoursubdomain.duckdns.org'일 수 있음.
        # owner는 거의 항상 '@'가 되어야 함 (yoursubdomain.duckdns.org 자체가 업데이트 대상).
        
        current_domain = self.config.get('domain', '')
        current_owner = self.config.get('owner', '@') # 기본값 '@'

        if not current_domain:
            # domain이 비어있으면 owner에서 추출 시도 (하위 호환성)
            if not current_owner or current_owner == '@':
                error_msg = f"{self.NAME.capitalize()} provider: 'domain' (your DuckDNS subdomain) is required."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
            
            # owner가 'yoursubdomain' 또는 'yoursubdomain.duckdns.org' 형태일 수 있음
            if current_owner.endswith(f".{self.ETLD}"):
                self.domain = current_owner # owner가 FQDN이면 domain으로 사용
                self.config['domain'] = self.domain # config 객체도 업데이트
                current_owner = '@' # owner는 @로 설정
            else: # owner가 서브도메인 파트만 가지고 있다고 가정
                self.domain = f"{current_owner}.{self.ETLD}"
                self.config['domain'] = self.domain
                current_owner = '@'
            self.config['owner'] = current_owner # owner를 @로 설정
            self.owner = current_owner # 인스턴스 변수도 업데이트
            self.logger.info(f"{self.NAME.capitalize()}: Adjusted domain to '{self.domain}' and owner to '{self.owner}'.")

        elif not current_domain.endswith(f".{self.ETLD}"):
            # domain이 'yoursubdomain' 형태이면 '.duckdns.org' 추가
            self.domain = f"{current_domain}.{self.ETLD}"
            self.config['domain'] = self.domain
            self.logger.info(f"{self.NAME.capitalize()}: Appended '.{self.ETLD}' to domain, new domain is '{self.domain}'.")
        else: # domain이 이미 'yoursubdomain.duckdns.org' 형태
            self.domain = current_domain

        # DuckDNS는 FQDN (yoursubdomain.duckdns.org)을 업데이트하므로, owner는 항상 '@'여야 함.
        if self.config.get('owner', '@') != '@':
            self.logger.warning(f"{self.NAME.capitalize()}: 'owner' is typically '@' for DuckDNS as the full subdomain (e.g., yourname.duckdns.org) is updated. Overriding owner to '@'.")
            self.config['owner'] = '@'
            self.owner = '@'


        # 필수 설정값 및 형식 확인
        if not self.token:
            error_msg = f"{self.NAME.capitalize()} provider: 'duckdns_token' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        if not self.TOKEN_REGEX.match(self.token):
            error_msg = f"{self.NAME.capitalize()} provider: 'duckdns_token' format is invalid (should be a UUID)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # 도메인 유효성 검사 (Go 코드의 regexDomain 및 레이블 수 검사)
        if not self.domain.endswith(f".{self.ETLD}"):
            error_msg = f"{self.NAME.capitalize()} provider: Domain '{self.domain}' must end with '.{self.ETLD}'."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # DuckDNS는 보통 yoursubdomain.duckdns.org 형태이므로, 레이블은 3개.
        # owner가 @가 아니면 (예: sub.yoursubdomain.duckdns.org) 레이블이 더 많아질 수 있으나,
        # DuckDNS는 단일 레벨 서브도메인만 지원하는 것으로 보임.
        # 여기서는 FQDN이 yoursubdomain.duckdns.org 형태라고 가정.
        if self.domain.count('.') != 1 or not self.domain.split('.')[0]: # yoursubdomain 파트가 있어야 함
             error_msg = f"{self.NAME.capitalize()} provider: Invalid domain format '{self.domain}'. Expected 'yoursubdomain.{self.ETLD}'."
             self.logger.error(error_msg)
             raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # domain은 yoursubdomain 부분, token은 필수. owner는 사실상 '@'로 고정.
        return ["duckdns_token", "domain"] 

    @staticmethod
    def get_optional_config_fields():
        # DuckDNS는 TTL 설정을 지원하지 않음. owner는 '@'로 간주.
        return {"owner": "@", "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on DuckDNS (free dynamic DNS service)."

    def _build_domain_for_query(self):
        """API의 'domains' 파라미터에 사용될 값 (yoursubdomain.duckdns.org)"""
        # __init__에서 self.domain이 이미 FQDN (yoursubdomain.duckdns.org)으로 설정됨.
        return self.domain

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        domain_for_query = self._build_domain_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {domain_for_query} (record type {record_type}) to IP: {ip_address}")

        params = {
            'verbose': 'true',
            'domains': domain_for_query, # yoursubdomain.duckdns.org
            'token': self.token,
        }

        if record_type == "AAAA": # IPv6
            params['ipv6'] = ip_address
        else: # IPv4 (기본)
            params['ip'] = ip_address
        
        # clearip=true 파라미터는 IP 주소를 명시적으로 전달하지 않을 때 사용 (자동 감지)
        # 여기서는 IP를 명시적으로 전달하므로 사용 안 함.

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                # HTTP 오류 발생 시, 응답 본문에 KO 메시지가 있을 수 있음
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text.lower().startswith("ko"):
                    error_message = "API Error: Update failed (KO response from server)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석 (Go 코드의 switch 문 참조)
            if len(response_text) < 2:
                return False, f"API Error: Response too short: '{response_text}'"
            
            response_prefix = response_text[:2].lower()

            if response_prefix == "ko":
                # KO 뒤에 추가 메시지가 있을 수 있음 (예: "KO - Invalid token")
                ko_message = response_text[2:].strip()
                if ko_message:
                    ko_message = f" ({ko_message})"
                return False, f"API Error: Update failed (KO response from server{ko_message})."
            elif response_prefix == "ok":
                # 성공. 응답에서 IP를 추출하여 확인.
                extracted_ip = self._extract_ip_from_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    msg = f"Successfully updated {domain_for_query} to {ip_address}. API Response: '{response_text}'"
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    msg = f"Update reported OK, but API returned IP {extracted_ip} instead of {ip_address}. Response: '{response_text}'"
                    self.logger.error(msg)
                    return False, msg # IP 불일치 시 실패로 처리
                else: # IP 추출 실패
                    msg = f"Update reported OK, but could not extract IP from response: '{response_text}'"
                    self.logger.warning(msg)
                    return False, msg # IP 확인 불가 시 실패로 처리 (Go 코드와 일치)
            else:
                return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_response(self, response_text, record_type):
        """응답 텍스트에서 IP 주소를 추출합니다 (Go의 ipextract.IPv4/IPv6 참조)."""
        # DuckDNS 응답 형식: "OK\n<IP Address>\n<Update Status>" (verbose=true 일 때)
        # 또는 "OK <IP Address>" 형태일 수도 있음.
        # 여기서는 응답 문자열 전체에서 IP를 찾음.
        lines = response_text.splitlines()
        # 두 번째 줄에 IP가 있을 수 있음 (verbose=true)
        # 또는 "OK 1.2.3.4" 처럼 첫 줄에 있을 수도 있음.
        # 여기서는 전체 텍스트에서 IP 패턴 검색
        
        ip_pattern_str = r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b' # IPv4
        if record_type == "AAAA":
            ip_pattern_str = r'\b(?:[A-F0-9]{1,4}:){2,7}(?:[A-F0-9]{1,4})\b' 
        
        match = re.search(ip_pattern_str, response_text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
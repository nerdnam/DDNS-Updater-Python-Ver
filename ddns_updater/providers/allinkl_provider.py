# ddns_updater/providers/allinkl_provider.py
import requests
import re # IP 주소 추출을 위해 (선택 사항, 응답 형식에 따라)

from .base_provider import BaseProvider

class AllinklProvider(BaseProvider):
    NAME = "allinkl"
    API_ENDPOINT = "https://dyndns.kasserver.com/"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('allinkl_username')
        self.password = self.config.get('allinkl_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (allinkl_username, allinkl_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        return ["allinkl_username", "allinkl_password", "domain", "owner"] # owner도 명시적으로 필요

    @staticmethod
    def get_optional_config_fields():
        return {"ttl": None} # ALL-INKL은 TTL 설정을 지원하지 않을 수 있음 (문서 확인)

    @staticmethod
    def get_description():
        return "Updates DNS records on ALL-INKL.com using their DynDNS API."

    def _build_hostname(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '':
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname = self._build_hostname()
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname} ({record_type}) to IP: {ip_address}")

        params = {'host': hostname}
        if record_type == "A": # IPv4
            params['myip'] = ip_address
        elif record_type == "AAAA": # IPv6
            params['myip6'] = ip_address
        else:
            return False, f"Unsupported record type: {record_type}. Only A or AAAA is supported."

        auth = (self.username, self.password) # HTTP Basic Authentication
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, auth=auth, headers=headers, timeout=timeout)
            
            # 응답 본문 읽기 (Go 코드의 utils.ReadAndCleanBody와 유사하게 처리)
            # 일반적으로 response.text는 이미 디코딩된 문자열을 제공
            response_text = response.text.strip() if response.text else ""

            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                return False, f"API Error: HTTP {response.status_code} - {response_text}"

            # Go 코드의 응답 문자열 분석 로직 적용
            if not response_text: # 빈 응답
                return False, "API Error: Received empty response from server."
            if response_text == "911":
                return False, "API Error: DNS server-side issue (911)."
            if response_text == "abuse":
                return False, "API Error: Account banned due to abuse."
            if response_text == "!donator": # Go 코드에서는 !donator, 문서 확인 필요
                return False, "API Error: Feature unavailable (donation required?)."
            if response_text == "badagent":
                return False, "API Error: User-Agent banned."
            if response_text == "badauth":
                return False, "API Error: Authentication failed (bad username/password)."
            if response_text == "nohost":
                return False, f"API Error: Hostname '{hostname}' does not exist or is not managed by this account."

            if "nochg" in response_text:
                # IP 주소가 변경되지 않았음을 의미. 응답에서 IP를 추출하여 확인하는 것이 더 확실할 수 있음.
                # Go 코드는 응답에서 IP를 추출하여 비교함.
                extracted_ip = self._extract_ip_from_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    msg = f"IP address {ip_address} for {hostname} is already up to date (nochg)."
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    # nochg인데 IP가 다르면 혼란스러움. API 문서를 봐야 함.
                    msg = f"IP address {ip_address} for {hostname} reported as 'nochg', but extracted IP is {extracted_ip}."
                    self.logger.warning(msg)
                    return False, msg # 또는 True, msg 로 처리하고 로깅만 할 수도 있음
                else:
                    # nochg인데 IP 추출 실패
                    msg = f"IP address {ip_address} for {hostname} reported as 'nochg', but could not extract IP from response: {response_text}"
                    self.logger.warning(msg)
                    return True, msg # 일단 성공으로 처리

            if "good" in response_text:
                # 업데이트 성공. 응답에서 IP를 추출하여 확인.
                extracted_ip = self._extract_ip_from_response(response_text, record_type)
                if extracted_ip and extracted_ip == ip_address:
                    msg = f"Successfully updated {hostname} to {ip_address} (good)."
                    self.logger.info(msg)
                    return True, msg
                elif extracted_ip:
                    # good인데 IP가 다르면 문제.
                    msg = f"Successfully updated {hostname} (good), but API returned IP {extracted_ip} instead of {ip_address}."
                    self.logger.error(msg)
                    return False, msg # 실패로 처리
                else:
                    # good인데 IP 추출 실패
                    msg = f"Successfully updated {hostname} (good), but could not extract IP from response: {response_text}"
                    self.logger.warning(msg)
                    return True, msg # 일단 성공으로 처리

            # 위의 조건에 해당하지 않는 응답
            return False, f"API Error: Unknown response from server: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"

    def _extract_ip_from_response(self, response_text, record_type):
        """응답 텍스트에서 IP 주소를 추출합니다 (Go의 ipextract.IPv4/IPv6 참조)."""
        # ALL-INKL 응답 형식에 따라 IP 추출 로직 구현 필요.
        # 예시: "good 1.2.3.4" 또는 "nochg 1.2.3.4" 형태일 수 있음.
        # 정규 표현식 사용이 유용할 수 있음.
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' # IPv4 예시
        if record_type == "AAAA":
            # IPv6 정규 표현식 (더 복잡함, 간단한 예시)
            ip_pattern = r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b' # 대소문자 구분 없음 가정
        
        match = re.search(ip_pattern, response_text, re.IGNORECASE)
        if match:
            return match.group(0)
        return None
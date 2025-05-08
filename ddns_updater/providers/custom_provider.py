# ddns_updater/providers/custom_provider.py
import re
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from .base_provider import BaseProvider

class CustomProvider(BaseProvider):
    NAME = "custom"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.update_url_template = self.config.get('custom_url')
        self.ipv4_key = self.config.get('custom_ipv4_key') # 사용자가 설정, 없으면 None
        self.ipv6_key = self.config.get('custom_ipv6_key') # 사용자가 설정, 없으면 None
        success_regex_str = self.config.get('custom_success_regex')
        
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not self.update_url_template:
            error_msg = f"{self.NAME.capitalize()} provider: 'custom_url' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        try:
            parsed_url = urlparse(self.update_url_template)
            if parsed_url.scheme != 'https':
                error_msg = f"{self.NAME.capitalize()} provider: 'custom_url' must use https scheme."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
        except Exception as e: # urlparse 실패 등
            error_msg = f"{self.NAME.capitalize()} provider: Invalid 'custom_url': {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        if not success_regex_str:
            error_msg = f"{self.NAME.capitalize()} provider: 'custom_success_regex' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        try:
            self.success_regex = re.compile(success_regex_str)
        except re.error as e:
            error_msg = f"{self.NAME.capitalize()} provider: Invalid 'custom_success_regex': {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # domain, owner는 Custom 프로바이더의 URL에 사용자가 직접 포함시킬 수도 있고,
        # URL 템플릿 변수 ({domain}, {owner})로 처리할 수도 있음.
        # 여기서는 URL과 정규식만 필수로 하고, 나머지는 선택적으로 사용자가 URL에 구성.
        return ["custom_url", "custom_success_regex"]

    @staticmethod
    def get_optional_config_fields():
        return {
            "custom_ipv4_key": None, # 예: "myip", "ipv4"
            "custom_ipv6_key": None, # 예: "myip6", "ipv6"
            "domain": None, # URL 템플릿에 사용 가능
            "owner": None,  # URL 템플릿에 사용 가능
            "ttl": None     # Custom URL이 TTL을 지원할 가능성은 낮음
        }

    @staticmethod
    def get_description():
        return "Updates DNS records using a user-defined custom URL and success regex."

    def _build_update_url(self, ip_address, record_type):
        """
        사용자 정의 URL 템플릿을 기반으로 실제 업데이트 URL을 구성합니다.
        URL 템플릿은 {ip}, {domain}, {owner}, {hostname} 변수를 지원할 수 있습니다.
        쿼리 파라미터는 ipv4_key/ipv6_key를 사용하여 추가됩니다.
        """
        # URL 템플릿 변수 치환
        # owner가 없거나 '@'이면 hostname은 domain과 동일
        owner_val = self.config.get('owner', '@')
        hostname_val = self.domain
        if owner_val and owner_val != '@':
            hostname_val = f"{owner_val}.{self.domain}"
            
        current_url = self.update_url_template.format(
            ip=ip_address,
            domain=self.domain,
            owner=owner_val, # '@' 또는 실제 owner 값
            hostname=hostname_val
        )

        # URL 파싱하여 쿼리 파라미터 추가
        parsed_url = urlparse(current_url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)

        ip_key_to_use = None
        if record_type == "A" and self.ipv4_key:
            ip_key_to_use = self.ipv4_key
        elif record_type == "AAAA" and self.ipv6_key:
            ip_key_to_use = self.ipv6_key
        
        if ip_key_to_use:
            # 기존 키가 있으면 덮어쓰고, 없으면 추가.
            # parse_qs는 값을 리스트로 반환하므로, 단일 값으로 설정.
            query_params[ip_key_to_use] = [ip_address] 
        
        # 수정된 쿼리 파라미터로 URL 재구성
        # urlencode는 리스트 값을 가진 딕셔너리를 올바르게 처리
        new_query_string = urlencode(query_params, doseq=True)
        
        # scheme, netloc, path, params, fragment는 유지하고 query만 변경
        final_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params, # 일반적으로 비어있음
            new_query_string,
            parsed_url.fragment
        ))
        return final_url

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        try:
            target_url = self._build_update_url(ip_address, record_type)
        except KeyError as e: # URL 템플릿에 필요한 변수가 config에 없는 경우
            error_msg = f"Failed to build custom URL. Missing placeholder in URL or config: {e}"
            self.logger.error(error_msg)
            return False, error_msg
            
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update using URL: {target_url}")

        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)
        
        # Custom URL은 HTTP Basic Auth 등을 사용자가 URL에 직접 포함시킬 수 있음 (예: https://user:pass@example.com)
        # requests는 이를 자동으로 처리함.

        try:
            response = requests.get(target_url, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                return False, f"Custom URL Error: HTTP {response.status_code} - {response_text}"

            if self.success_regex.search(response_text):
                # 성공 정규식 매칭. 요청한 IP로 업데이트되었다고 가정.
                success_message = f"Successfully updated using custom URL. Response matched success regex. IP set to {ip_address} (assumed)."
                self.logger.info(success_message)
                return True, success_message
            else:
                error_message = f"Custom URL Error: Response did not match success regex. Response: '{response_text}'"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"Custom URL Request Error: {e}"
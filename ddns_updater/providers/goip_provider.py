# ddns_updater/providers/goip_provider.py
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/비밀번호 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class GoipProvider(BaseProvider):
    NAME = "goip"
    API_HOST = "www.goip.de" # 기본 호스트, goip.it의 경우 조정 필요
    API_PATH = "/setip"
    # GoIP 도메인 패턴 (goip.de 또는 goip.it)
    DOMAIN_REGEX = re.compile(r"^.+\.(goip\.de|goip\.it)$", re.IGNORECASE)
    DEFAULT_ETLD = "goip.de" # 하위 호환성용

    def __init__(self, config, logger):
        super().__init__(config, logger) # domain, owner 초기화
        self.username = self.config.get('goip_username')
        self.password = self.config.get('goip_password')
        
        # GoIP의 domain/owner 처리 (Go 코드 로직 반영)
        current_domain = self.config.get('domain', '')
        current_owner = self.config.get('owner', '@')

        if not current_domain or current_domain.lower() == self.DEFAULT_ETLD or current_domain.lower() == "goip.it":
            effective_etld = self.DEFAULT_ETLD
            if current_domain.lower() == "goip.it":
                effective_etld = "goip.it"
            
            if not current_owner or current_owner == '@':
                error_msg = f"{self.NAME.capitalize()} provider: 'domain' (your GoIP subdomain part) is required when domain is set to eTLD or empty."
                self.logger.error(error_msg)
                raise ValueError(error_msg)

            owner_parts = current_owner.split('.')
            last_owner_part = owner_parts[-1]
            self.domain = f"{last_owner_part}.{effective_etld}"
            self.config['domain'] = self.domain
            
            if len(owner_parts) > 1:
                current_owner = ".".join(owner_parts[:-1])
            else:
                current_owner = '@'
            self.config['owner'] = current_owner
            self.owner = current_owner
            self.logger.info(f"{self.NAME.capitalize()}: Adjusted domain to '{self.domain}' and owner to '{self.owner}'.")
        
        elif not self.DOMAIN_REGEX.match(current_domain):
             # domain이 FQDN 형태이지만 .goip.de/.goip.it로 끝나지 않는 경우 (거의 없을 듯)
             # 또는 사용자가 yoursubdomain.goip.de 형태로 입력한 경우
             if not (current_domain.endswith(".goip.de") or current_domain.endswith(".goip.it")):
                error_msg = f"{self.NAME.capitalize()} provider: Domain '{current_domain}' must end with '.goip.de' or '.goip.it'."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
             self.domain = current_domain # 이미 FQDN 형태
        else: # domain이 이미 yoursubdomain.goip.de/it 형태
            self.domain = current_domain

        # owner가 '*'이면 오류 (Go 코드 참조)
        if self.config.get('owner') == '*':
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard owner ('*') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # 도메인 레이블 수 검사 (Go 코드 참조, FQDN 기준)
        # self.domain은 이제 FQDN (예: yoursubdomain.goip.de)
        # owner는 FQDN의 일부 (예: sub) 또는 @
        # GoIP는 보통 yoursubdomain.goip.de 형태이므로, FQDN 레이블은 3개.
        # owner가 @가 아니면 (예: sub.yoursubdomain.goip.de) 레이블이 더 많아짐.
        # Go 코드의 maxDomainLabels = 3은 FQDN 기준.
        # 여기서는 self.domain (FQDN)의 레이블 수를 검사.
        if self.domain.count('.') + 1 > 3: # 예: a.b.c.goip.de -> 4개 레이블
             self.logger.warning(f"{self.NAME.capitalize()}: Domain '{self.domain}' has more than 3 labels, which might not be standard for GoIP.")


        # 필수 설정값 확인
        if not all([self.username, self.password]): # domain은 위에서 처리됨
            error_msg = f"{self.NAME.capitalize()} provider: 'goip_username' and 'goip_password' are required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # domain은 yoursubdomain 부분 또는 FQDN, username, password는 필수.
        # owner는 선택적 또는 '@'로 간주 가능.
        return ["goip_username", "goip_password", "domain"] 

    @staticmethod
    def get_optional_config_fields():
        # GoIP API가 TTL 설정을 지원하는지 확인 필요. owner는 기본값 '@'.
        return {"owner": "@", "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on GoIP (goip.de, goip.it) using their DynDNS API."

    def _build_subdomain_for_query(self):
        """API의 'subdomain' 파라미터에 사용될 FQDN 구성"""
        # __init__에서 self.domain이 이미 FQDN (yoursubdomain.goip.de/it)으로 설정됨.
        # owner는 FQDN의 일부이거나 @.
        # GoIP API는 'subdomain' 파라미터에 전체 FQDN을 기대.
        owner_val = self.config.get('owner', '@')
        if owner_val == '@' or owner_val == '' or owner_val is None:
            return self.domain
        # owner가 있으면 self.domain (예: yoursubdomain.goip.de) 앞에 붙임.
        # 하지만 __init__에서 self.domain이 이미 최종 FQDN이 되도록 조정했으므로,
        # 여기서는 self.domain을 그대로 사용하거나,
        # BaseProvider의 _build_fqdn() 같은 공통 메소드를 사용하는 것이 좋음.
        # 여기서는 Go 코드의 p.BuildDomainName()을 따름.
        if owner_val == '@' or owner_val == '' or owner_val is None:
            return self.domain
        # self.domain은 yoursubdomain.goip.de 형태. owner는 그 앞의 것.
        # 예: owner=sub, domain=host.goip.de -> sub.host.goip.de
        # 하지만 __init__에서 domain이 이미 최종 FQDN이 되도록 했으므로,
        # p.BuildDomainName()은 owner + "." + domain (여기서 domain은 eTLD가 아닌 부분)
        # 여기서는 self.owner와 self.domain을 조합하여 FQDN을 만듦.
        # self.domain은 youractualdomain.goip.de/it
        # self.owner는 @ 또는 그 앞의 서브도메인
        if self.owner == '@' or self.owner == '' or self.owner is None:
            return self.domain
        return f"{self.owner}.{self.domain}"


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        subdomain_for_query = self._build_subdomain_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {subdomain_for_query} (record type {record_type}) to IP: {ip_address}")

        # API 호스트 결정 (goip.de 또는 goip.it)
        # self.domain은 FQDN (예: yoursubdomain.goip.de)
        api_host_to_use = self.API_HOST # 기본 www.goip.de
        if self.domain.endswith(".goip.it"):
            # GoIP.it의 API 엔드포인트가 www.goip.it인지, 아니면 www.goip.de로 통일되는지 확인 필요.
            # Go 코드는 www.goip.de로 고정. 여기서는 일단 따름.
            # 만약 다르다면: api_host_to_use = "www.goip.it"
            pass


        # URL 구성 (Userinfo + Query Params)
        # Go 코드는 Userinfo와 Query Params 둘 다 사용. Userinfo가 우선될 것임.
        userinfo_user = quote(self.username, safe='')
        userinfo_pass = quote(self.password, safe='')
        
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{api_host_to_use}{self.API_PATH}"
        
        params = {
            'subdomain': subdomain_for_query,
            'username': self.username, # Userinfo와 중복이지만 Go 코드에 있음
            'password': self.password, # Userinfo와 중복이지만 Go 코드에 있음
            'shortResponse': 'true',
        }

        if record_type == "AAAA": # IPv6
            params['ip6'] = ip_address
        else: # IPv4 (기본)
            params['ip'] = ip_address
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                error_message = f"API Error: HTTP {response.status_code}"
                if "zugriff verweigert" in response_text.lower(): # 접근 거부 (독일어)
                    error_message = "API Error: Authentication failed (zugriff verweigert)."
                elif response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

            # 상태 코드 200일 때 응답 본문 분석
            expected_success_prefix = f"{subdomain_for_query} ({ip_address})"
            if response_text.lower().startswith(expected_success_prefix.lower()):
                success_message = f"Successfully updated {subdomain_for_query} to {ip_address}."
                if response_text:
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            elif "zugriff verweigert" in response_text.lower():
                return False, "API Error: Authentication failed (zugriff verweigert)."
            # GoIP는 "nochg" 같은 응답이 있는지 확인 필요.
            # 현재 Go 코드는 FQDN (IP) 형태의 응답만 성공으로 간주.
            else:
                return False, f"API Error: Unknown or unexpected success response: '{response_text}'"

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
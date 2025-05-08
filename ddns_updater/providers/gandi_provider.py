# ddns_updater/providers/gandi_provider.py
import json
import requests

from .base_provider import BaseProvider

class GandiProvider(BaseProvider):
    NAME = "gandi"
    API_BASE_URL = "https://api.gandi.net/v5/livedns"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.personal_access_token = self.config.get('gandi_personal_access_token')
        self.api_key = self.config.get('gandi_api_key') # Deprecated, but supported for backward compatibility
        
        try:
            self.ttl = int(self.config.get('gandi_ttl', 300)) # 기본 TTL 300초 (5분)
            if self.ttl < 300: # Gandi 최소 TTL 확인 필요
                self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} is below common minimums, using 300. Check Gandi's minimum TTL.")
                self.ttl = 300
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('gandi_ttl')}', using default 300.")
            self.ttl = 300
            
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인 (인증 정보)
        if not self.personal_access_token and not self.api_key:
            error_msg = f"{self.NAME.capitalize()} provider: Either 'gandi_personal_access_token' or 'gandi_api_key' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not self.domain: # domain은 BaseProvider에서 처리되지만, 여기서도 명시적 확인 가능
            error_msg = f"{self.NAME.capitalize()} provider: 'domain' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # owner 기본값 설정 (Gandi API는 owner가 @여도 명시적으로 전달해야 할 수 있음)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")


    @staticmethod
    def get_required_config_fields():
        # domain, owner는 API 경로에 사용됨. 인증 정보는 둘 중 하나.
        return ["domain", "owner"] # __init__에서 인증 정보 조합 확인

    @staticmethod
    def get_optional_config_fields():
        return {
            "gandi_personal_access_token": None,
            "gandi_api_key": None, # Deprecated
            "gandi_ttl": 300 # Gandi 기본 TTL 또는 권장값 확인 필요
        }

    @staticmethod
    def get_description():
        return "Updates DNS records on Gandi using their LiveDNS API (v5)."

    def _build_headers(self):
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if self.personal_access_token:
            headers['Authorization'] = f'Bearer {self.personal_access_token}'
        elif self.api_key:
            self.logger.warning(f"{self.NAME.capitalize()}: Using deprecated API Key for authentication. Consider switching to a Personal Access Token.")
            headers['X-Api-Key'] = self.api_key
        return headers

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        
        # Gandi API 경로: /domains/{domain}/records/{owner}/{recordType}
        # owner가 비어있거나 '@'일 경우 API 경로에 어떻게 표현되는지 확인 필요.
        # 일반적으로 '@'는 루트 도메인을 의미하며, API 경로에는 '@' 문자 그대로 사용될 수 있음.
        # Go 코드는 owner를 그대로 사용.
        
        endpoint_path = f"/domains/{self.domain}/records/{owner_val}/{record_type}"
        target_url = f"{self.API_BASE_URL}{endpoint_path}"

        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {owner_val}.{self.domain} ({record_type}) to IP: {ip_address} via {target_url}")

        # Gandi API는 rrset_values를 배열로 받음.
        # IPv6 주소의 경우, Go 코드의 ip.Unmap()은 IPv4 매핑된 IPv6 주소를 순수 IPv4로 변환.
        # Python의 netaddr 또는 ipaddress 라이브러리로 유사한 처리 가능하나,
        # 일반적으로 DDNS 클라이언트에 전달되는 IP는 이미 적절한 형태일 것으로 가정.
        # 여기서는 전달된 ip_address를 그대로 사용.
        payload = {
            'rrset_values': [ip_address],
        }
        if self.ttl is not None: # TTL이 0이 아니거나 (Go 코드 기준), 유효한 값일 때만 포함
            payload['rrset_ttl'] = self.ttl

        headers = self._build_headers()
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # Gandi API는 PUT 요청으로 레코드 생성 또는 업데이트
            response = requests.put(target_url, json=payload, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # Gandi API는 성공 시 201 Created 반환
            if response.status_code == 201:
                # 성공 메시지에 API 응답 내용 포함 가능 (예: {"message": "DNS Record Created"})
                success_message = f"Successfully updated {owner_val}.{self.domain} to {ip_address} (API status 201 Created)."
                try:
                    response_json = response.json()
                    if response_json and 'message' in response_json:
                        success_message += f" API Message: '{response_json['message']}'"
                except json.JSONDecodeError:
                    if response_text: # JSON 아니지만 내용이 있다면 추가
                         success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            else:
                # HTTP 오류 발생
                error_message = f"API Error: HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    # Gandi 오류 응답은 'message', 'errors', 'cause' 등을 포함할 수 있음
                    if 'message' in error_data:
                        error_message += f" - Message: {error_data['message']}"
                    elif 'errors' in error_data and isinstance(error_data['errors'], list) and error_data['errors']:
                        err_details = []
                        for err_item in error_data['errors']:
                            if isinstance(err_item, dict) and 'description' in err_item:
                                err_details.append(err_item['description'])
                        if err_details:
                             error_message += f" - Details: {'; '.join(err_details)}"
                    elif response_text:
                         error_message += f" - {response_text}"
                except json.JSONDecodeError:
                    if response_text:
                        error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
# ddns_updater/providers/godaddy_provider.py
import json
import re
import requests

from .base_provider import BaseProvider

class GodaddyProvider(BaseProvider):
    NAME = "godaddy"
    API_BASE_URL = "https://api.godaddy.com/v1"
    # GoDaddy API Key 형식: 8-14자리 영숫자 + '_' + 21-22자리 영숫자
    API_KEY_REGEX = re.compile(r"^[A-Za-z0-9]{8,14}_[A-Za-z0-9]{21,22}$")

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('godaddy_api_key')
        self.api_secret = self.config.get('godaddy_api_secret')
        
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정 (GoDaddy API는 owner가 @여도 명시적으로 전달해야 할 수 있음)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 및 형식 확인
        if not all([self.api_key, self.api_secret, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (godaddy_api_key, godaddy_api_secret, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not self.API_KEY_REGEX.match(self.api_key):
            error_msg = f"{self.NAME.capitalize()} provider: 'godaddy_api_key' format is invalid."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 API 경로에 사용됨.
        return ["godaddy_api_key", "godaddy_api_secret", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # GoDaddy API는 레코드 업데이트 시 TTL, priority, weight, port, service, proto 등도 지원.
        # 필요시 이들을 optional_fields로 추가하고 update_record에서 사용 가능.
        # 여기서는 Go 코드의 단순성을 따라 TTL 등은 일단 제외.
        return {"ttl": None} # 예시, 실제 지원 여부 및 기본값 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on GoDaddy using their API (v1)."

    def _build_headers(self):
        return {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'sso-key {self.api_key}:{self.api_secret}'
        }

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        
        # GoDaddy API 경로: /v1/domains/{domain}/records/{recordType}/{owner}
        # owner가 비어있거나 '@'일 경우 API 경로에 어떻게 표현되는지 확인 필요.
        # Go 코드는 owner를 그대로 사용.
        
        endpoint_path = f"/domains/{self.domain}/records/{record_type}/{owner_val}"
        target_url = f"{self.API_BASE_URL}{endpoint_path}"

        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {owner_val}.{self.domain} ({record_type}) to IP: {ip_address} via {target_url}")

        # GoDaddy API는 요청 본문으로 [{ "data": "IP_ADDRESS" }] 형태의 배열을 기대.
        payload = [{'data': ip_address}]
        # TTL 등 다른 필드도 필요시 payload 객체 내에 추가 가능 (API 문서 확인)
        # 예: payload = [{'data': ip_address, 'ttl': self.config.get('ttl', 600)}]

        headers = self._build_headers()
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # GoDaddy API는 PUT 요청으로 레코드 생성 또는 업데이트
            response = requests.put(target_url, json=payload, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # GoDaddy API는 성공 시 200 OK 반환 (본문은 비어있을 수 있음)
            if response.status_code == 200:
                # 성공 메시지에 API 응답 내용 포함 가능 (보통 비어있음)
                success_message = f"Successfully updated {owner_val}.{self.domain} to {ip_address} (API status 200 OK)."
                if response_text: # 내용이 있다면 추가
                     success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            else:
                # HTTP 오류 발생
                error_message = f"API Error: HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if 'message' in error_data:
                        error_message += f" - Message: {error_data['message']}"
                        if (response.status_code == 403 and 
                            error_data['message'] == "Authenticated user is not allowed access"):
                            error_message += " - (This might be related to API key permissions or domain ownership. See GoDaddy developer portal or qdm12/ddns-updater#707)"
                    elif 'code' in error_data: # 다른 형식의 오류 메시지
                         error_message += f" - Code: {error_data['code']}"
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
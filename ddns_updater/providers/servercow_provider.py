# ddns_updater/providers/servercow_provider.py
import json
import requests

from .base_provider import BaseProvider

class ServercowProvider(BaseProvider):
    NAME = "servercow"
    API_BASE_URL = "https://api.servercow.de/dns/v1"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('servercow_username')
        self.password = self.config.get('servercow_password')
        
        try:
            # Servercow API 문서에서 TTL 기본값 및 유효 범위 확인 필요.
            # Go 코드는 설정된 TTL을 그대로 사용.
            self.ttl = int(self.config.get('servercow_ttl', 300)) # 예시 기본값 300
            if self.ttl <= 0: # 또는 다른 유효성 검사
                self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} might be invalid, using 300. Check Servercow's TTL requirements.")
                self.ttl = 300
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('servercow_ttl')}', using default 300.")
            self.ttl = 300
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정 (Go 코드 참조)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (servercow_username, servercow_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Go 코드의 v3: enforce owner is not empty 및 wildcard 검사
        owner_val = self.config.get('owner', '@')
        if not owner_val: # owner가 빈 문자열인 경우 (거의 없을 듯, @가 기본이므로)
             error_msg = f"{self.NAME.capitalize()} provider: 'owner' cannot be empty (use '@' for root domain)."
             self.logger.error(error_msg)
             raise ValueError(error_msg)
        if '*' in owner_val: # 와일드카드 포함 금지
            error_msg = f"{self.NAME.capitalize()} provider: Wildcard in owner ('{owner_val}') is not allowed."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 Servercow에서 name 필드에 사용됨.
        return ["servercow_username", "servercow_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"servercow_ttl": 300} # Servercow 기본 TTL 또는 권장값 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on Servercow.de using their API (v1)."

    def _build_headers(self):
        return {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Auth-Username': self.username,
            'X-Auth-Password': self.password
        }

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        # Servercow API는 'name' 필드에 owner 값 (@는 빈 문자열로)을 기대.
        name_for_api = owner_val if owner_val != '@' else ""
        
        # API 경로: /dns/v1/domains/{domain}
        endpoint_path = f"/domains/{self.domain}"
        target_url = f"{self.API_BASE_URL}{endpoint_path}"

        log_hostname = f"{owner_val}.{self.domain}"
        if owner_val == '@': log_hostname = self.domain

        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {log_hostname} ({record_type}) to IP: {ip_address} via POST to {target_url}")

        payload = {
            "type": record_type,
            "name": name_for_api,
            "content": ip_address,
            "ttl": self.ttl
        }

        headers = self._build_headers()
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # Servercow API는 POST 요청으로 레코드 생성 또는 업데이트 (UPSERT 방식)
            response = requests.post(target_url, json=payload, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # Go 코드에서는 response.StatusCode > http.StatusUnsupportedMediaType (415) 이면 오류.
            # 즉, 200-2xx 범위는 성공으로 간주하고 JSON 파싱 시도.
            # 여기서는 200 OK만 성공으로 간주하고, 나머지는 오류로 처리. (API 문서 확인 필요)
            if response.status_code == 200:
                try:
                    response_data = response.json()
                except json.JSONDecodeError:
                    # 성공했으나 JSON 파싱 실패 (예: 빈 응답인데 성공으로 간주해야 할 때)
                    if not response_text: # 빈 응답이면 성공으로 간주 가능성
                        self.logger.info(f"Successfully updated {log_hostname} to {ip_address} (API status 200 OK, empty response).")
                        return True, f"Update successful (200 OK, empty response)."
                    self.logger.error(f"{self.NAME.capitalize()} API Error: Failed to decode JSON response for 200 OK. Body: '{response_text}'")
                    return False, f"API Error: Failed to decode JSON response for 200 OK. Body: '{response_text}'"

                api_message = response_data.get('message', '').lower()
                api_error = response_data.get('error', '') # 오류 시 이 필드에 상세 내용

                if api_message == "ok":
                    # 성공. 요청한 IP로 업데이트되었다고 가정.
                    # Servercow API가 업데이트된 IP를 반환하는지 확인 필요. Go 코드는 요청 IP를 반환.
                    success_message = f"Successfully updated {log_hostname} to {ip_address}."
                    if api_error: # 성공 메시지에도 error 필드가 있을 수 있음 (정보성)
                        success_message += f" API Info: '{api_error}'"
                    self.logger.info(success_message)
                    return True, success_message
                else:
                    # message가 "ok"가 아닌 경우 (오류)
                    error_details = api_error if api_error else api_message
                    return False, f"API Error: Update unsuccessful. Details: '{error_details}'"
            else: # HTTP 상태 코드가 200이 아님
                error_message = f"API Error: HTTP {response.status_code}"
                try: # 오류 응답도 JSON일 수 있음
                    error_data = response.json()
                    api_err_msg = error_data.get('error', error_data.get('message', response_text))
                    error_message += f" - {api_err_msg}"
                except json.JSONDecodeError:
                    if response_text:
                        error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
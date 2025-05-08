# ddns_updater/providers/dondominio_provider.py
import json
import requests

from .base_provider import BaseProvider

class DondominioProvider(BaseProvider):
    NAME = "dondominio"
    API_ENDPOINT = "https://dondns.dondominio.com/json/"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('dondominio_username')
        self.api_key = self.config.get('dondominio_api_key')
        
        # 하위 호환성: password가 있으면 api_key로 사용
        if not self.api_key and self.config.get('dondominio_password'):
            self.api_key = self.config.get('dondominio_password')
            self.logger.info(f"{self.NAME.capitalize()}: Using 'dondominio_password' as 'dondominio_api_key' for backward compatibility.")

        # self.domain 은 BaseProvider 에서 처리
        # owner 기본값 설정 (Go 코드 참조)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.api_key, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dondominio_username, dondominio_api_key/dondominio_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 DonDominio에서 host 구성에 필요.
        # api_key 또는 password (하위 호환) 중 하나 필요.
        return ["dondominio_username", "domain", "owner"] # __init__에서 api_key/password 조합 확인

    @staticmethod
    def get_optional_config_fields():
        # DonDominio API가 TTL 설정을 지원하는지 확인 필요
        return {"dondominio_api_key": None, "dondominio_password": None, "ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on DonDominio (Spain) using their API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # DonDominio는 IPv4/IPv6 구분 없이 'ip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        params = {
            'user': self.username,
            'apikey': self.api_key,
            'host': hostname_for_query,
            'ip': ip_address,
            'lang': 'en' # Go 코드에서 사용, API 문서에서 확인 필요
        }

        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json' # API가 JSON 응답을 반환하므로 명시
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            response.raise_for_status() # HTTP 오류 발생 시 예외 발생 (4xx, 5xx)
            
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                # JSON 디코딩 실패 시, 응답 본문을 그대로 오류 메시지에 포함
                response_text = response.text.strip() if response.text else "Empty response body"
                self.logger.error(f"{self.NAME.capitalize()} API Error: Failed to decode JSON response. Body: '{response_text}'")
                return False, f"API Error: Failed to decode JSON response. Body: '{response_text}'"

            self.logger.debug(f"{self.NAME.capitalize()} API Response: {response_data}")

            if response_data.get('success') is True:
                success_message = f"Successfully updated {hostname_for_query} to {ip_address} (assumed)."
                # 성공 메시지가 있다면 로그에 추가
                messages = response_data.get('messages', [])
                if messages:
                    success_message += f" API Messages: {', '.join(messages)}"
                self.logger.info(success_message)
                return True, success_message
            else:
                # success가 false이거나 없는 경우
                error_messages = response_data.get('messages', ["Unknown error from API."])
                full_error_message = f"API Error: Update unsuccessful. Messages: {', '.join(error_messages)}"
                self.logger.error(full_error_message)
                return False, full_error_message

        except requests.exceptions.HTTPError as e:
            # HTTP 오류 발생 시 (raise_for_status()에 의해), 응답 본문이 JSON일 수 있음
            error_message = f"API HTTP Error: {e.response.status_code}"
            try:
                error_data = e.response.json()
                messages = error_data.get('messages', [])
                if messages:
                    error_message += f" - Messages: {', '.join(messages)}"
                else:
                    error_message += f" - {e.response.text.strip() if e.response.text else 'No error body'}"
            except json.JSONDecodeError:
                error_message += f" - {e.response.text.strip() if e.response.text else 'No error body'}"
            self.logger.error(error_message)
            return False, error_message
        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
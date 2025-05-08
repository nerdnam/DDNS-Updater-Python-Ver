# ddns_updater/providers/njalla_provider.py
import json
import requests

from .base_provider import BaseProvider

class NjallaProvider(BaseProvider):
    NAME = "njalla"
    API_ENDPOINT = "https://njal.la/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('njalla_api_key')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' 
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.api_key, self.domain]): # owner는 기본값 처리
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (njalla_api_key, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Njalla에서 'h' 파라미터 구성에 필요.
        return ["njalla_api_key", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Njalla API가 TTL 설정을 지원하는지 확인 필요 (일반적으로 DynDNS 계열은 미지원)
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Njalla using their API."

    def _build_hostname_for_query(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname_for_query = self._build_hostname_for_query()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname_for_query} (record type {record_type}) to IP: {ip_address}")

        params = {
            'h': hostname_for_query,
            'k': self.api_key,
        }
        if record_type == "AAAA": # IPv6
            params['aaaa'] = ip_address
        else: # IPv4 (기본)
            params['a'] = ip_address
        
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json' # Njalla API는 JSON 응답
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            try:
                response_data = response.json()
            except json.JSONDecodeError:
                # JSON 디코딩 실패 시, 상태 코드와 원본 텍스트로 오류 판단
                if response.status_code == 200: # 성공했어야 하는데 JSON이 아님
                    self.logger.error(f"{self.NAME.capitalize()} API Error: Expected JSON response for 200 OK, but got: '{response_text}'")
                    return False, f"API Error: Expected JSON response for 200 OK, but got: '{response_text}'"
                else: # 오류 상태 코드인데 JSON이 아님
                    self.logger.error(f"API Error: HTTP {response.status_code} - Failed to decode JSON response: '{response_text}'")
                    return False, f"API Error: HTTP {response.status_code} - Non-JSON error response: '{response_text}'"

            api_message = response_data.get('message', '')

            # HTTP 상태 코드 기반 처리 (Go 코드 참조)
            if response.status_code == 200:
                if api_message == "record updated":
                    value_data = response_data.get('value', {})
                    returned_ip_str = ""
                    if record_type == "AAAA" and isinstance(value_data, dict):
                        returned_ip_str = value_data.get('AAAA', '')
                    elif record_type == "A" and isinstance(value_data, dict):
                        returned_ip_str = value_data.get('A', '')
                    
                    if not returned_ip_str:
                        msg = f"Update reported success ('record updated'), but no IP found in 'value' field of response: {response_data}"
                        self.logger.warning(msg)
                        return False, msg # IP 확인 불가 시 실패로 처리

                    if returned_ip_str == ip_address:
                        success_message = f"Successfully updated {hostname_for_query} to {ip_address}. API Message: '{api_message}'"
                        self.logger.info(success_message)
                        return True, success_message
                    else:
                        msg = f"Update reported success ('record updated'), but API returned IP {returned_ip_str} instead of {ip_address}."
                        self.logger.error(msg)
                        return False, msg # IP 불일치 시 실패로 처리
                else:
                    return False, f"API Error: Unknown success response message: '{api_message}'. Full response: {response_data}"

            elif response.status_code == 401: # Unauthorized
                error_msg = f"API Error: Authentication failed (HTTP 401)."
                if api_message: error_msg += f" Message: '{api_message}'"
                return False, error_msg
            elif response.status_code == 500: # Internal Server Error (Njalla는 잘못된 요청에도 500 사용)
                error_msg = f"API Error: Bad request or server error (HTTP 500)."
                if api_message: error_msg += f" Message: '{api_message}'"
                return False, error_msg
            else: # 그 외 다른 오류 상태 코드
                error_msg = f"API Error: HTTP {response.status_code}"
                if api_message: error_msg += f" - Message: '{api_message}'"
                elif response_text: error_msg += f" - {response_text}" # JSON 파싱 실패 시 원본 사용
                return False, error_msg

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
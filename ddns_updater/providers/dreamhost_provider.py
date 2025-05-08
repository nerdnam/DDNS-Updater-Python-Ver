# ddns_updater/providers/dreamhost_provider.py
import json
import uuid # for unique_id
import re   # for API key validation
import requests
from urllib.parse import urlencode

from .base_provider import BaseProvider

class DreamhostProvider(BaseProvider):
    NAME = "dreamhost"
    API_ENDPOINT = "https://api.dreamhost.com/"
    API_KEY_REGEX = re.compile(r"^[a-zA-Z0-9]{16}$")

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('dreamhost_api_key')
        # self.domain 은 BaseProvider 에서 처리
        # owner 기본값 설정 (Go 코드 참조)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 및 API 키 형식 확인
        if not self.api_key:
            error_msg = f"{self.NAME.capitalize()} provider: 'dreamhost_api_key' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        if not self.API_KEY_REGEX.match(self.api_key):
            error_msg = f"{self.NAME.capitalize()} provider: 'dreamhost_api_key' is invalid (must be 16 alphanumeric characters)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        if not self.domain: # domain은 BaseProvider에서 처리되지만, 여기서도 명시적 확인 가능
            error_msg = f"{self.NAME.capitalize()} provider: 'domain' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 DreamHost에서 record 구성에 필요.
        return ["dreamhost_api_key", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # DreamHost API는 TTL 설정을 지원하지 않는 것으로 보임 (문서 확인 필요).
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on DreamHost using their API."

    def _build_common_query_params(self):
        """공통 쿼리 파라미터 생성 (Go의 defaultURLValues 참조)"""
        return {
            'key': self.api_key,
            'unique_id': str(uuid.uuid4()), # 각 요청마다 새로운 UUID 생성
            'format': 'json'
        }

    def _build_record_name_for_api(self):
        """API의 'record' 파라미터에 사용될 FQDN 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def _make_api_request(self, params_dict):
        """DreamHost API 요청 실행 (항상 GET)"""
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json'
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # 모든 요청은 GET이며, 파라미터는 URL에 인코딩됨
            response = requests.get(self.API_ENDPOINT, params=params_dict, headers=headers, timeout=timeout)
            response.raise_for_status() # HTTP 오류 발생 시 예외 발생
            
            response_data = response.json()
            self.logger.debug(f"{self.NAME.capitalize()} API Response for cmd '{params_dict.get('cmd')}': {response_data}")

            if response_data.get('result') != 'success':
                error_message = response_data.get('data', 'Unknown API error (result not success).')
                full_error_msg = f"API Error: Command '{params_dict.get('cmd')}' failed. Result: {response_data.get('result')}, Data: {error_message}"
                self.logger.error(full_error_msg)
                return None, full_error_msg
            
            return response_data, None # 성공 시 전체 JSON 데이터 반환
            
        except requests.exceptions.HTTPError as e:
            error_body = e.response.text if e.response else "No response body"
            self.logger.error(f"DreamHost API HTTP error: {e.response.status_code if e.response else 'N/A'} - {error_body}")
            return None, f"API HTTP Error: {e.response.status_code if e.response else 'N/A'} - {error_body}"
        except requests.exceptions.RequestException as e:
            self.logger.error(f"DreamHost API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            response_text = response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'
            self.logger.error(f"DreamHost API JSON decode error: {e}. Response: {response_text}")
            return None, f"API JSON Decode Error: {e}"

    def _list_records(self):
        """dns-list_records API 호출 (Go의 getRecords 참조)"""
        params = self._build_common_query_params()
        params['cmd'] = 'dns-list_records'
        
        data, error_msg = self._make_api_request(params)
        if error_msg:
            return None, error_msg
        return data.get('data', []), None # 'data'는 레코드 리스트

    def _add_record(self, record_name, record_type, ip_address):
        """dns-add_record API 호출 (Go의 createRecord 참조)"""
        self.logger.info(f"DreamHost: Adding record: {record_name} ({record_type}) -> {ip_address}")
        params = self._build_common_query_params()
        params.update({
            'cmd': 'dns-add_record',
            'record': record_name,
            'type': record_type,
            'value': ip_address
            # DreamHost API는 TTL 설정을 지원하지 않는 것으로 보임
        })
        
        data, error_msg = self._make_api_request(params)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        # 성공 시 'data' 필드에 "Record added!" 같은 메시지가 올 수 있음
        return True, data.get('data', "Record added successfully (assumed).")


    def _remove_record(self, record_name, record_type, ip_address_to_remove):
        """dns-remove_record API 호출 (Go의 removeRecord 참조)"""
        self.logger.info(f"DreamHost: Removing old record: {record_name} ({record_type}) -> {ip_address_to_remove}")
        params = self._build_common_query_params()
        params.update({
            'cmd': 'dns-remove_record',
            'record': record_name,
            'type': record_type,
            'value': ip_address_to_remove
        })
        
        data, error_msg = self._make_api_request(params)
        if error_msg:
            return False, error_msg
        return True, data.get('data', "Record removed successfully (assumed).")


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        record_name_for_api = self._build_record_name_for_api()
        self.logger.info(f"DreamHost: Attempting to update {record_name_for_api} ({record_type}) to IP: {ip_address}")

        # 1. 기존 레코드 조회
        records_data, error_msg = self._list_records()
        if error_msg:
            return False, f"Failed to list existing records: {error_msg}"

        old_ip_value = None
        found_record_is_editable = False

        for record_entry in records_data:
            if (record_entry.get('type') == record_type and
                record_entry.get('record') == record_name_for_api):
                
                if record_entry.get('editable') == "0":
                    msg = f"DreamHost: Record {record_name_for_api} ({record_type}) is not editable."
                    self.logger.error(msg)
                    return False, msg
                
                found_record_is_editable = True
                old_ip_value = record_entry.get('value')
                break # 일치하는 첫 번째 레코드 사용

        if found_record_is_editable and old_ip_value == ip_address:
            msg = f"DreamHost: IP address {ip_address} for {record_name_for_api} is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # 2. 새 IP로 레코드 추가 (기존 레코드 존재 여부와 관계없이 일단 추가 시도)
        add_success, add_msg = self._add_record(record_name_for_api, record_type, ip_address)
        if not add_success:
            return False, f"Failed to add new record: {add_msg}"
        
        self.logger.info(f"DreamHost: Successfully added record for new IP {ip_address}. Message: {add_msg}")

        # 3. 이전 IP의 레코드가 존재했다면 삭제
        if found_record_is_editable and old_ip_value and old_ip_value != ip_address:
            remove_success, remove_msg = self._remove_record(record_name_for_api, record_type, old_ip_value)
            if not remove_success:
                # 새 레코드는 추가되었지만 이전 레코드 삭제 실패. 사용자에게 알림.
                warning_msg = f"Successfully added new IP, but failed to remove old record ({old_ip_value}): {remove_msg}. Manual cleanup may be required."
                self.logger.warning(warning_msg)
                return True, warning_msg # 새 IP는 설정되었으므로 일단 성공으로 처리하나 경고
            self.logger.info(f"DreamHost: Successfully removed old record for IP {old_ip_value}. Message: {remove_msg}")
        
        return True, f"Successfully updated {record_name_for_api} to {ip_address} (add new, remove old if existed)."
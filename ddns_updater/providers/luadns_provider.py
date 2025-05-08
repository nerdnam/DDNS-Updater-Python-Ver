# ddns_updater/providers/luadns_provider.py
import json
import re
import requests
from urllib.parse import quote # URL에 사용자 이름/토큰 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class LuadnsProvider(BaseProvider):
    NAME = "luadns"
    API_BASE_URL = "https://api.luadns.com/v1"
    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9-_.+]+@[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,10}$")

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.email = self.config.get('luadns_email')
        self.token = self.config.get('luadns_token')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 및 형식 확인
        if not all([self.email, self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (luadns_email, luadns_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not self.EMAIL_REGEX.match(self.email):
            error_msg = f"{self.NAME.capitalize()} provider: 'luadns_email' format is invalid."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not self.token: # 토큰 빈 문자열 검사 (Go 코드와 동일)
            error_msg = f"{self.NAME.capitalize()} provider: 'luadns_token' cannot be empty."
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 LuaDNS에서 레코드 name 구성에 필요.
        return ["luadns_email", "luadns_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # LuaDNS API는 레코드 업데이트 시 TTL을 포함하므로, 설정 가능하게 할 수 있음.
        return {"ttl": None} # 기본 TTL은 API에서 가져오거나, LuaDNS 기본값 사용

    @staticmethod
    def get_description():
        return "Updates DNS records on LuaDNS using their API (v1)."

    def _get_auth(self):
        """HTTP Basic Authentication 튜플 반환"""
        return (self.email, self.token)

    def _parse_luadns_error(self, response_content_str, status_code):
        """LuaDNS API 오류 응답 파싱 (Go의 getErrorMessage/decodeErrorMessage 유사)"""
        try:
            error_data = json.loads(response_content_str)
            if isinstance(error_data, dict):
                status = error_data.get('status', f'HTTP {status_code}')
                message = error_data.get('message', 'No specific error message from API.')
                return f"Status: {status}, Message: {message}"
        except json.JSONDecodeError:
            pass # 파싱 실패 시 원본 반환
        return response_content_str if response_content_str else f"HTTP {status_code}"


    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None):
        """LuaDNS API 요청 실행"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json'
        }
        if method.upper() in ["POST", "PUT"]:
            headers['Content-Type'] = 'application/json'
        
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, auth=self._get_auth(), headers=headers, timeout=timeout)
            elif method.upper() == "POST": # LuaDNS는 레코드 생성 시 POST 사용 가능성 (문서 확인)
                response = requests.post(url, json=json_payload, auth=self._get_auth(), headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=json_payload, auth=self._get_auth(), headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method for LuaDNS: {method}")
                return None, f"Unsupported HTTP method: {method}"

            response_content_str = response.text 

            if 200 <= response.status_code < 300:
                if not response_content_str and response.status_code in [200, 204]:
                    return {}, None 
                return response.json(), None
            else: 
                error_details = self._parse_luadns_error(response_content_str, response.status_code)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                self.logger.error(f"LuaDNS API call to {method} {url} failed. {error_msg}")
                if response.status_code == 404: # Not Found (Zone 또는 Record)
                    return {"error_type": "NotFound"}, error_msg
                if response.status_code == 401: # Unauthorized
                    return {"error_type": "AuthError"}, error_msg
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"LuaDNS API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            self.logger.error(f"LuaDNS API JSON decode error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}")
            return None, f"API JSON Decode Error: {e}"

    def _get_zone_id(self):
        """설정된 domain에 해당하는 Zone ID 조회 (Go의 getZoneID 참조)"""
        self.logger.debug(f"LuaDNS: Getting Zone ID for domain '{self.domain}'")
        endpoint_path = "/zones"
        
        data, error_msg = self._make_api_request("GET", endpoint_path)
        if error_msg:
            return None, error_msg
        
        if isinstance(data, list): # 응답이 zone 객체 배열
            for zone in data:
                if isinstance(zone, dict) and zone.get('name') == self.domain:
                    zone_id = zone.get('id')
                    if zone_id and isinstance(zone_id, int):
                        self.logger.info(f"LuaDNS: Found Zone ID: {zone_id} for domain '{self.domain}'")
                        return zone_id, None
            # 일치하는 zone 없음
            msg = f"LuaDNS: Zone for domain '{self.domain}' not found among {len(data)} zones."
            self.logger.error(msg)
            return None, msg # Go 코드는 errors.ErrZoneNotFound 반환
        else:
            msg = f"LuaDNS: Unexpected response format when getting zones. Expected list, got {type(data)}. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _get_record_info(self, zone_id, owner_val, record_type_filter):
        """특정 Zone ID 내에서 owner와 type이 일치하는 레코드 정보 조회 (Go의 getRecord 참조)."""
        # LuaDNS는 레코드 이름(name)에 FQDN + TRAILING DOT을 사용.
        fqdn_with_dot = self.domain + "."
        if owner_val != '@' and owner_val != '':
            fqdn_with_dot = f"{owner_val}.{self.domain}."

        self.logger.debug(f"LuaDNS: Getting record info for name '{fqdn_with_dot}' (type: {record_type_filter}) in zone ID {zone_id}")
        endpoint_path = f"/zones/{zone_id}/records"
        
        data, error_msg = self._make_api_request("GET", endpoint_path)
        if error_msg:
            return None, error_msg # record_object, error_message
        
        if isinstance(data, list):
            for record_entry in data:
                if (isinstance(record_entry, dict) and
                    record_entry.get('type') == record_type_filter and
                    record_entry.get('name') == fqdn_with_dot):
                    
                    # 필요한 모든 정보(id, name, type, content, ttl)를 포함한 record_entry 반환
                    self.logger.info(f"LuaDNS: Found record for name '{fqdn_with_dot}': {record_entry}")
                    return record_entry, None 
            
            self.logger.info(f"LuaDNS: No existing record found for name '{fqdn_with_dot}' (type: {record_type_filter}) in zone ID {zone_id}.")
            return None, None # 레코드 없음 (오류는 아님)
        else:
            msg = f"LuaDNS: Unexpected response format when listing records for zone ID {zone_id}. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _update_existing_record(self, zone_id, existing_record_data, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        record_id = existing_record_data.get('id')
        record_name = existing_record_data.get('name') # FQDN with dot
        record_type = existing_record_data.get('type')
        
        self.logger.info(f"LuaDNS: Updating RecordId {record_id} ({record_name}, type {record_type}) in zone ID {zone_id} to IP {ip_address}")
        
        endpoint_path = f"/zones/{zone_id}/records/{record_id}"
        
        # 업데이트 페이로드는 기존 레코드 정보를 기반으로 content만 변경
        payload = {
            "id": record_id,
            "name": record_name,
            "type": record_type,
            "content": ip_address,
            "ttl": existing_record_data.get('ttl', self.config.get('ttl', 300)), # 기존 TTL 또는 설정/기본 TTL
            # LuaDNS API가 다른 필드(예: prio)를 요구하거나 변경 가능하게 하는지 확인 필요
        }
        # TTL 설정이 optional_config_fields에 있고, 사용자가 설정했다면 그 값을 우선 사용
        user_ttl = self.config.get('ttl')
        if user_ttl is not None:
            try: payload['ttl'] = int(user_ttl)
            except ValueError: self.logger.warning(f"Invalid TTL '{user_ttl}' in config, using existing/default.")


        data, error_msg = self._make_api_request("PUT", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        if isinstance(data, dict) and data.get('id') == record_id:
            updated_ip = data.get('content')
            if updated_ip == ip_address:
                self.logger.info(f"LuaDNS: Successfully updated RecordId {record_id}. IP confirmed: {updated_ip}")
                return True, f"Record updated successfully (ID: {record_id})."
            else:
                msg = f"LuaDNS: Successfully updated RecordId {record_id}, but API returned IP '{updated_ip}' instead of '{ip_address}'."
                self.logger.warning(msg)
                return True, msg # 일단 성공으로 처리하나 경고
        else:
            msg = f"LuaDNS: Failed to update record or unexpected response format. Response: {data}"
            self.logger.error(msg)
            return False, msg

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        # 1. Zone ID 가져오기
        zone_id, error_msg = self._get_zone_id()
        if error_msg or not zone_id:
            return False, f"Failed to get Zone ID for domain '{self.domain}': {error_msg or 'Zone not found.'}"

        owner_val = self.config.get('owner', '@')
        # LuaDNS는 레코드 이름에 FQDN + TRAILING DOT 사용
        fqdn_with_dot_to_update = self.domain + "."
        if owner_val != '@' and owner_val != '':
            fqdn_with_dot_to_update = f"{owner_val}.{self.domain}."

        self.logger.info(f"LuaDNS: Attempting to update {fqdn_with_dot_to_update} ({record_type}) in zone ID {zone_id} to IP: {ip_address}")

        # 2. 기존 레코드 정보 조회
        existing_record, error_msg = self._get_record_info(zone_id, owner_val, record_type)
        
        if error_msg: # 조회 중 심각한 오류 발생
            return False, f"Failed to get existing record info: {error_msg}"
        
        if existing_record is None: # 레코드 없음
            # LuaDNS API는 레코드 생성 기능이 있는지 확인 필요.
            # Go 코드는 레코드 없으면 오류. 여기서는 일단 Go 코드 동작을 따름.
            # (만약 POST /v1/zones/{zoneID}/records 로 생성 가능하다면 _create_dns_record 구현)
            msg = f"LuaDNS: Record for name '{fqdn_with_dot_to_update}' (type: {record_type}) in zone ID {zone_id} does not exist. Auto-creation not implemented (matching Go client behavior)."
            self.logger.error(msg)
            return False, msg

        # 레코드 존재
        current_ip = existing_record.get('content')
        if current_ip == ip_address:
            # TTL 등 다른 속성도 같은지 확인하는 로직 추가 가능
            msg = f"LuaDNS: IP address {ip_address} for name '{fqdn_with_dot_to_update}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        self.logger.info(f"LuaDNS: Record for name '{fqdn_with_dot_to_update}' ({record_type}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
        update_success, update_msg = self._update_existing_record(zone_id, existing_record, ip_address)
        return update_success, update_msg
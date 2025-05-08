# ddns_updater/providers/hetzner_provider.py
import json
import requests

from .base_provider import BaseProvider

class HetznerProvider(BaseProvider):
    NAME = "hetzner"
    API_BASE_URL = "https://dns.hetzner.com/api/v1"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('hetzner_token')
        self.zone_id = self.config.get('hetzner_zone_id')
        
        try:
            # Go 코드에서는 TTL 0이면 1로 설정. Hetzner 최소 TTL 확인 필요.
            # Hetzner API 문서는 TTL을 필수로 요구하지 않음 (생성 시). 업데이트 시에는?
            # 여기서는 기본값 300, 0 이하면 경고 후 기본값 사용.
            self.ttl = int(self.config.get('hetzner_ttl', 300)) 
            if self.ttl <= 0: # Hetzner 최소 TTL이 60초일 수 있음
                self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} might be too low or invalid, using 300. Check Hetzner's minimum TTL (e.g., 60).")
                self.ttl = 300
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('hetzner_ttl')}', using default 300.")
            self.ttl = 300
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정 (Hetzner API는 'name' 필드에 owner(@, www 등)를 기대)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.token, self.zone_id, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (hetzner_token, hetzner_zone_id, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 API의 'name' 필드에 사용됨.
        return ["hetzner_token", "hetzner_zone_id", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"hetzner_ttl": 300} # Hetzner 기본 TTL 또는 권장값 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on Hetzner DNS using their API (v1)."

    def _build_headers(self):
        return {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Auth-Api-Token': self.token
        }

    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None):
        """Hetzner DNS API 요청 실행"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = self._build_headers()
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=json_payload, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=json_payload, headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method for Hetzner: {method}")
                return None, f"Unsupported HTTP method: {method}"

            # HTTP 오류 발생 시 예외를 발생시키지 않고 상태 코드로 처리 (Go 코드 방식)
            response_content_str = response.text # 오류 파싱을 위해 미리 읽음

            if 200 <= response.status_code < 300:
                if not response_content_str and response.status_code in [200, 204]: # 200 OK with empty body, or 204 No Content
                    return {}, None # 빈 딕셔너리 (성공)
                return response.json(), None
            else: # 오류 발생
                error_details = response_content_str # Hetzner 오류는 보통 간단한 메시지
                try: # JSON 형태의 오류일 수도 있음
                    error_data = json.loads(response_content_str)
                    if isinstance(error_data, dict) and "error" in error_data and "message" in error_data["error"]:
                        error_details = f"Code: {error_data['error'].get('code', 'N/A')}, Message: {error_data['error']['message']}"
                    elif isinstance(error_data, dict) and "message" in error_data: # 다른 형태의 오류
                         error_details = error_data["message"]
                except json.JSONDecodeError:
                    pass # 이미 response_content_str 사용
                
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                self.logger.error(f"Hetzner API call to {method} {url} failed. {error_msg}")
                if response.status_code == 404 and endpoint_path.startswith("/records") and len(endpoint_path.split('/')) > 3 : # GET /records/zone_id?name=...&type=...
                     # GET /records?zone_id=... 에서 404는 레코드 없음을 의미할 수 있음 (Go 코드의 ErrReceivedNoResult)
                     # 하지만 GET /records/{id} 에서 404는 ID가 없는 것.
                     # 여기서는 getRecordID의 404를 ErrReceivedNoResult로 처리하므로, 그 외 404는 일반 오류.
                     pass # _get_record_info 에서 특별 처리
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Hetzner API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            self.logger.error(f"Hetzner API JSON decode error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}")
            return None, f"API JSON Decode Error: {e}"

    def _get_record_info(self, owner_val, record_type_filter):
        """지정된 레코드의 ID와 현재 IP 값을 조회 (Go의 getRecordID 참조)."""
        self.logger.debug(f"Hetzner: Getting record info for owner '{owner_val}' (type: {record_type_filter}) in zone '{self.zone_id}'")
        
        endpoint_path = "/records"
        params = {
            'zone_id': self.zone_id,
            'name': owner_val, # Hetzner는 owner (@, www 등)를 name으로 사용
            'type': record_type_filter,
            'page': 1,
            'per_page': 1 # 정확히 하나의 레코드만 찾기 위함
        }

        data, error_msg = self._make_api_request("GET", endpoint_path, query_params=params)
        
        if error_msg:
            # Go 코드는 GET /records 에서 404를 ErrReceivedNoResult로 처리.
            # _make_api_request에서 일반 오류로 처리되므로, 여기서 404를 특별히 구분할 필요는 없음.
            # 다만, 호출하는 쪽에서 error_msg 내용을 보고 판단해야 함.
            # 또는 _make_api_request가 404일 때 특정 값을 반환하도록 수정.
            # 여기서는 일단 error_msg를 그대로 반환.
            return None, None, False, error_msg # record_id, current_ip, record_exists, error_message
        
        if data and 'records' in data:
            records = data.get('records', [])
            if len(records) == 1:
                record = records[0]
                record_id = record.get('id')
                current_ip = record.get('value')
                if record_id:
                    self.logger.info(f"Hetzner: Found RecordId: {record_id} for owner '{owner_val}' with IP: {current_ip}")
                    return record_id, current_ip, True, None
                else: # ID가 없는 경우 (이론적으로는 발생 안 함)
                    msg = f"Hetzner: Found a record for '{owner_val}', but RecordId is missing."
                    self.logger.error(msg)
                    return None, None, False, msg
            elif len(records) == 0:
                self.logger.info(f"Hetzner: No existing record found for owner '{owner_val}' (type: {record_type_filter}).")
                return None, None, False, None # 레코드 없음
            else: # len(records) > 1
                msg = f"Hetzner: Multiple records found for owner '{owner_val}' (type: {record_type_filter}). This should not happen with per_page=1."
                self.logger.warning(msg)
                return None, None, False, msg
        else:
            msg = f"Hetzner: Failed to get record info or unexpected response format from /records. Response: {data}"
            self.logger.error(msg)
            return None, None, False, msg

    def _create_dns_record(self, owner_val, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"Hetzner: Creating new {record_type} record for owner '{owner_val}' in zone '{self.zone_id}' with IP {ip_address}")
        
        endpoint_path = "/records"
        payload = {
            'type': record_type,
            'name': owner_val, # owner (@, www 등)
            'value': ip_address,
            'zone_id': self.zone_id,
            'ttl': self.ttl
        }

        data, error_msg = self._make_api_request("POST", endpoint_path, json_payload=payload)
        if error_msg:
            return None, error_msg # record_id, error_message
        
        if data and 'record' in data and data['record'].get('id'):
            new_record = data['record']
            record_id = new_record['id']
            # 생성된 레코드의 IP도 확인 (Go 코드 참조)
            created_ip = new_record.get('value')
            if created_ip != ip_address:
                msg = f"Hetzner: Record created (ID: {record_id}), but created IP ({created_ip}) does not match target IP ({ip_address})."
                self.logger.error(msg)
                return None, msg # 생성은 되었으나 IP 불일치
                
            self.logger.info(f"Hetzner: Successfully created record. New RecordId: {record_id}, IP: {created_ip}")
            return record_id, None
        else:
            msg = f"Hetzner: Failed to create record or no RecordId in response. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _update_dns_record(self, record_id, owner_val, record_type, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        self.logger.info(f"Hetzner: Updating RecordId {record_id} (owner '{owner_val}', type {record_type}) in zone '{self.zone_id}' to IP {ip_address}")
        
        endpoint_path = f"/records/{record_id}"
        payload = {
            'type': record_type,
            'name': owner_val,
            'value': ip_address,
            'zone_id': self.zone_id, # 업데이트 시에도 zone_id 필요
            'ttl': self.ttl
        }

        data, error_msg = self._make_api_request("PUT", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        if data and 'record' in data:
            updated_record = data['record']
            updated_ip = updated_record.get('value')
            if updated_ip == ip_address:
                self.logger.info(f"Hetzner: Successfully updated RecordId {record_id}. New IP confirmed: {updated_ip}")
                return True, f"Successfully updated RecordId {record_id} to IP {ip_address}."
            else:
                msg = f"Hetzner: Successfully updated RecordId {record_id}, but API returned IP '{updated_ip}' instead of '{ip_address}'."
                self.logger.warning(msg)
                return True, msg # 일단 성공으로 처리하나 경고
        else:
            msg = f"Hetzner: Failed to update record or unexpected response format. Response: {data}"
            self.logger.error(msg)
            return False, msg

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"Hetzner: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) in zone '{self.zone_id}' to IP: {ip_address}")

        record_id, current_ip, record_exists, error_msg = self._get_record_info(owner_val, record_type)
        
        if error_msg: # _get_record_info 에서 심각한 오류 발생
            return False, f"Failed to get existing record info: {error_msg}"
        
        if not record_exists: # 레코드 없음
            self.logger.info(f"Hetzner: Record for owner '{owner_val}' (type: {record_type}) not found. Creating new one.")
            new_record_id, create_msg = self._create_dns_record(owner_val, record_type, ip_address)
            if new_record_id:
                return True, create_msg # 생성 성공 메시지
            else:
                return False, create_msg # 생성 실패 메시지
        
        # 레코드 존재
        if current_ip == ip_address:
            # TTL도 같은지 확인하는 로직 추가 가능
            msg = f"Hetzner: IP address {ip_address} for owner '{owner_val}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        self.logger.info(f"Hetzner: Record for owner '{owner_val}' ({record_type}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
        success, msg = self._update_dns_record(record_id, owner_val, record_type, ip_address)
        return success, msg
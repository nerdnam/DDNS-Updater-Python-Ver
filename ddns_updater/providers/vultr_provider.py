# ddns_updater/providers/vultr_provider.py
import json
import requests

from .base_provider import BaseProvider

class VultrProvider(BaseProvider):
    NAME = "vultr"
    API_BASE_URL = "https://api.vultr.com/v2"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('vultr_api_key')
        
        try:
            # Vultr API 문서에서 TTL 기본값 및 유효 범위 확인 필요.
            # Go 코드는 설정된 TTL을 그대로 사용.
            self.ttl = int(self.config.get('vultr_ttl', 300)) # 예시 기본값 300
            if self.ttl <= 0: # 또는 다른 유효성 검사
                self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} might be invalid, using 300. Check Vultr's TTL requirements.")
                self.ttl = 300
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('vultr_ttl')}', using default 300.")
            self.ttl = 300
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' # Vultr는 name 필드에 owner(@, www)를 사용
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.api_key, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (vultr_api_key, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Vultr에서 레코드의 name 필드에 사용됨.
        return ["vultr_api_key", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"vultr_ttl": 300} # Vultr 기본 TTL 또는 권장값 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on Vultr using their API (v2)."

    def _build_headers(self, include_content_type=False):
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        if include_content_type:
            headers['Content-Type'] = 'application/json'
        return headers

    def _parse_vultr_error(self, response_content_str, status_code):
        """Vultr API 오류 응답 파싱 (Go의 parseJSONErrorOrFullBody 참조)"""
        try:
            error_data = json.loads(response_content_str)
            if isinstance(error_data, dict) and 'error' in error_data:
                return error_data['error']
        except json.JSONDecodeError:
            pass 
        return response_content_str if response_content_str else f"HTTP {status_code}"

    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None):
        """Vultr API 요청 실행"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        is_post_put_patch = method.upper() in ["POST", "PUT", "PATCH"]
        headers = self._build_headers(include_content_type=is_post_put_patch)
        timeout = self.config.get('http_timeout_seconds', 10)
        
        self.logger.debug(f"Vultr API Request: {method} {url}")
        if query_params: self.logger.debug(f"Query Params: {query_params}")
        if json_payload: self.logger.debug(f"Payload: {json_payload}")

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=json_payload, headers=headers, timeout=timeout)
            elif method.upper() == "PATCH": # Vultr는 업데이트에 PATCH 사용
                response = requests.patch(url, json=json_payload, headers=headers, timeout=timeout)
            # Vultr는 레코드 삭제 시 DELETE /v2/domains/{domainName}/records/{recordId} 사용
            # elif method.upper() == "DELETE":
            #     response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                return None, f"Unsupported HTTP method for Vultr: {method}"

            response_content_str = response.text 
            self.logger.debug(f"Vultr API Response Status: {response.status_code}, Body: '{response_content_str}'")

            # Vultr API 성공: GET/PATCH 200 OK, POST 201 Created, PUT(레코드수정은PATCH) 204 No Content (업데이트 성공 시)
            # Go 코드는 POST 성공 시 201, PATCH 성공 시 204를 기대.
            if method.upper() == "POST" and response.status_code == 201:
                 try: return response.json() if response_content_str else {}, None
                 except json.JSONDecodeError: return {}, None
            elif method.upper() == "PATCH" and response.status_code == 204: # No Content for successful PATCH
                 return {}, None # 성공, 본문 없음
            elif method.upper() == "GET" and response.status_code == 200:
                 try: return response.json() if response_content_str else {}, None
                 except json.JSONDecodeError: return {}, None
            else: # 오류 또는 예상치 못한 성공 코드
                error_details = self._parse_vultr_error(response_content_str, response.status_code)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                
                # Go 코드의 상태 코드별 오류 매핑 참조
                if response.status_code == 400: # Bad Request
                    return {"error_type": "BadRequest", "message": error_details}, error_msg
                if response.status_code in [401, 403]: # Unauthorized, Forbidden
                    return {"error_type": "AuthError", "message": error_details}, error_msg
                if response.status_code == 404: # Not Found (Domain or Record)
                    return {"error_type": "NotFound", "message": error_details}, error_msg
                
                self.logger.error(f"Vultr API call to {method} {url} failed. {error_msg}")
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e: 
            return None, f"API JSON Decode Error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}"


    def _get_record_info(self, owner_val, record_type_filter):
        """특정 레코드의 ID와 현재 IP 조회 (Go의 getRecord 참조)."""
        self.logger.debug(f"Vultr: Getting record info for owner '{owner_val}' on domain '{self.domain}' (type: {record_type_filter})")
        endpoint_path = f"/domains/{self.domain}/records"
        params = {'per_page': 500} # Go 코드와 동일하게 설정
        
        data, error_msg = self._make_api_request("GET", endpoint_path, query_params=params)
        
        if error_msg:
            # 404는 도메인 자체가 없을 수 있음
            if isinstance(data, dict) and data.get("error_type") == "NotFound":
                 self.logger.info(f"Vultr: Domain '{self.domain}' not found or no records for it.")
                 return None, None, False, f"Domain '{self.domain}' not found or no records. Detail: {data.get('message', error_msg)}"
            return None, None, False, error_msg # record_id, current_ip, record_exists, error_message
        
        if data and 'records' in data and isinstance(data['records'], list):
            records_list = data['records']
            for record_entry in records_list:
                if isinstance(record_entry, dict):
                    # Vultr API는 'name' 필드에 owner (@, www 등)를 사용.
                    if (record_entry.get('type') == record_type_filter and
                        record_entry.get('name') == owner_val):
                        
                        record_id_str = record_entry.get('id') # Vultr ID는 문자열 (UUID)
                        current_ip = record_entry.get('data') # Vultr는 'data' 필드에 IP 저장
                        if record_id_str:
                            self.logger.info(f"Vultr: Found RecordId: {record_id_str} for owner '{owner_val}' with IP: {current_ip}")
                            return record_id_str, current_ip, True, None
            
            self.logger.info(f"Vultr: No existing record found for owner '{owner_val}' (type: {record_type_filter}) on domain '{self.domain}'.")
            return None, None, False, None # 레코드 없음
        else:
            msg = f"Vultr: Unexpected response format when listing records for domain '{self.domain}'. Response: {data}"
            self.logger.error(msg)
            return None, None, False, msg


    def _create_dns_record(self, owner_val, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"Vultr: Creating new {record_type} record for owner '{owner_val}' on domain '{self.domain}' with IP {ip_address}")
        endpoint_path = f"/domains/{self.domain}/records"
        
        payload = {
            "type": record_type,
            "name": owner_val, # owner (@, www 등)
            "data": ip_address,
            "ttl": self.ttl, # Vultr는 TTL을 숫자로 받음
            # "priority": 0, # MX 등 다른 타입에 필요할 수 있음
        }

        data, error_msg = self._make_api_request("POST", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg 
        
        # 성공 시 (201 Created), 응답 본문에 생성된 레코드 정보 포함 ('record' 키 아래)
        if isinstance(data, dict) and 'record' in data and isinstance(data['record'], dict):
            created_record = data['record']
            created_ip = created_record.get('data')
            created_id = created_record.get('id')
            if created_ip == ip_address:
                self.logger.info(f"Vultr: Successfully created record. ID: {created_id}, IP: {created_ip}")
                return True, f"Record created successfully (ID: {created_id})."
            else:
                msg = f"Vultr: Record created (ID: {created_id}), but created IP ({created_ip}) does not match target IP ({ip_address})."
                self.logger.error(msg)
                return False, msg
        else:
            # 성공했으나 (201) 응답에서 확인 불가
            msg = f"Vultr: Record creation reported success (201 Created), but could not verify from response: {data}"
            self.logger.warning(msg)
            return True, msg # 일단 성공으로 처리


    def _update_existing_record(self, record_id_str, owner_val, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조 - PATCH 사용)."""
        self.logger.info(f"Vultr: Updating RecordId {record_id_str} (owner '{owner_val}') on domain '{self.domain}' to IP {ip_address}")
        
        endpoint_path = f"/domains/{self.domain}/records/{record_id_str}"
        # Vultr API는 PATCH 시 변경할 필드만 포함.
        # Go 코드는 data, name, ttl을 모두 보냄. name은 변경 불가일 수 있음.
        payload = {
            "data": ip_address,
            # "name": owner_val, # 보통 PATCH에서는 식별자 외의 필드는 변경하지 않음. API 문서 확인.
            # "ttl": self.ttl,   # TTL도 업데이트하려면 추가
        }
        # 만약 name, ttl도 업데이트해야 한다면 payload에 추가.
        # 여기서는 Go 코드와 유사하게 name, ttl도 보내도록 함 (API가 허용한다면).
        payload["name"] = owner_val
        if self.ttl is not None: # Vultr는 TTL 0을 허용할 수 있음 (기본값 사용 의미)
             payload["ttl"] = self.ttl


        data, error_msg = self._make_api_request("PATCH", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        # PATCH 성공 시 (204 No Content), 응답 본문 없음.
        # Go 코드는 응답 본문의 error 필드를 확인하는데, 204면 본문이 없어야 함.
        # 여기서는 _make_api_request에서 204면 성공으로 처리.
        return True, f"Record (ID: {record_id_str}) update reported success (204 No Content)."


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"Vultr: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        # 1. 기존 레코드 정보 (ID 및 현재 IP) 조회
        record_id, current_ip, record_exists, error_msg = self._get_record_info(owner_val, record_type)
        
        if error_msg: 
            if isinstance(record_id, dict) and record_id.get("error_type") == "NotFound":
                 # get_record_info에서 레코드 못 찾으면 record_exists=False, error_msg=None 반환
                 pass # 아래 record_exists에서 처리
            else:
                 return False, f"Failed to get existing record info: {error_msg}"
        
        if not record_exists:
            self.logger.info(f"Vultr: Record for owner '{owner_val}' (type: {record_type}) not found. Creating new one.")
            create_success, create_msg = self._create_dns_record(owner_val, record_type, ip_address)
            return create_success, create_msg
        
        # 레코드 존재
        if current_ip == ip_address:
            # TTL 등 다른 속성도 같은지 확인하는 로직 추가 가능
            msg = f"Vultr: IP address {ip_address} for owner '{owner_val}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        self.logger.info(f"Vultr: Record ID {record_id} for owner '{owner_val}' ({record_type}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
        update_success, update_msg = self._update_existing_record(record_id, owner_val, ip_address)
        return update_success, update_msg
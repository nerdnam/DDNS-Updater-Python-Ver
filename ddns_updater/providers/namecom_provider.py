# ddns_updater/providers/namecom_provider.py
import json
import requests
from urllib.parse import quote # URL에 사용자 이름/토큰 포함 시 필요할 수 있음

from .base_provider import BaseProvider

class NamecomProvider(BaseProvider):
    NAME = "namecom"
    API_BASE_URL = "https://api.name.com/v4"
    MIN_TTL = 300 # Name.com 최소 TTL (문서 확인 필요)

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('namecom_username')
        self.token = self.config.get('namecom_token') # API Token
        
        try:
            # TTL은 선택적, 설정되지 않으면 API 기본값 사용 (payload에서 omitempty)
            user_ttl_str = self.config.get('namecom_ttl')
            if user_ttl_str is not None:
                self.ttl = int(user_ttl_str)
                if self.ttl < self.MIN_TTL:
                    self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} is below minimum {self.MIN_TTL}, using {self.MIN_TTL}.")
                    self.ttl = self.MIN_TTL
            else:
                self.ttl = None # API 기본값 사용
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('namecom_ttl')}', API default will be used.")
            self.ttl = None
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.username, self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (namecom_username, namecom_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Name.com에서 host 필드에 사용됨.
        return ["namecom_username", "namecom_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"namecom_ttl": None} # 기본값은 API 서버에서 결정

    @staticmethod
    def get_description():
        return "Updates DNS records on Name.com using their API (v4)."

    def _get_auth(self):
        """HTTP Basic Authentication 튜플 반환"""
        return (self.username, self.token)

    def _parse_namecom_error(self, response_content_str, status_code):
        """Name.com API 오류 응답 파싱 (Go의 parseErrorResponse 참조)"""
        try:
            error_data = json.loads(response_content_str)
            if isinstance(error_data, dict):
                message = error_data.get('message', '')
                details = error_data.get('details', '')
                if message and details:
                    return f"Message: {message}, Details: {details}"
                elif message:
                    return message
                elif details: # details만 있는 경우는 드물지만
                    return f"Details: {details}"
        except json.JSONDecodeError:
            pass 
        return response_content_str if response_content_str else f"HTTP {status_code}"

    def _verify_success_response_body(self, response_content_str, sent_ip_str):
        """성공 응답 본문 검증 (Go의 verifySuccessResponseBody 참조)"""
        try:
            data = json.loads(response_content_str)
            # Name.com API는 생성/수정 시 업데이트된 레코드 객체를 반환할 수 있음
            # 예: {"id":123,"domainName":"example.com","host":"@","fqdn":"example.com.","type":"A","answer":"1.2.3.4",...}
            # 또는 단순히 성공 메시지만 올 수도 있음. API 문서 확인 필요.
            # Go 코드는 'answer' 필드를 확인.
            if isinstance(data, dict) and 'answer' in data:
                received_ip = data.get('answer')
                if received_ip == sent_ip_str:
                    return True, "IP match in response."
                else:
                    return False, f"IP mismatch: sent {sent_ip_str}, received {received_ip} in response."
            # Go 코드는 answer 필드가 없으면 오류로 처리하지 않음 (sentIP와 비교 불가)
            # Name.com API가 항상 answer를 반환하는지 확인 필요.
            # 만약 answer가 항상 없다면, HTTP 상태 코드로만 성공 판단.
            self.logger.debug("No 'answer' field in success response to verify IP, assuming success based on status code.")
            return True, "Success (no IP in response to verify)." 
        except json.JSONDecodeError:
            # JSON 파싱 실패 시, 응답이 단순 텍스트 성공 메시지일 수 있음 (API 문서 확인)
            # 또는 오류일 수 있으나, 이 함수는 성공 응답 검증용.
            self.logger.warning(f"Could not parse success response as JSON: {response_content_str}")
            return True, f"Success (non-JSON response: {response_content_str})." # 일단 성공으로 간주


    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None):
        """Name.com API 요청 실행"""
        # Name.com API는 URL에 User:Password 형태의 Basic Auth를 사용
        # requests 라이브러리의 auth 파라미터 사용
        
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json' # Go 코드의 setHeaders 참조
        }
        if method.upper() in ["POST", "PUT"]:
            headers['Content-Type'] = 'application/json'
        
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, auth=self._get_auth(), headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=json_payload, auth=self._get_auth(), headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=json_payload, auth=self._get_auth(), headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method for Name.com: {method}")
                return None, f"Unsupported HTTP method: {method}"

            response_content_str = response.text 

            # Name.com API 성공: 200 OK (GET, PUT), 201 Created (POST는 보통 201이지만, Go 코드는 200/201 모두 OK로 처리)
            if response.status_code in [200, 201]:
                return response.json() if response_content_str else {}, None # 성공 시 JSON 또는 빈 객체
            else: 
                error_details = self._parse_namecom_error(response_content_str, response.status_code)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                self.logger.error(f"Name.com API call to {method} {url} failed. {error_msg}")
                # 특정 오류 메시지에 따른 내부 오류 타입 매핑 (Go 코드 참조)
                if "not found" in error_details.lower():
                    return {"error_type": "RecordNotFound"}, error_msg # 또는 DomainNotFound
                if "permission denied" in error_details.lower() or "unauthenticated" in error_details.lower():
                    return {"error_type": "AuthError"}, error_msg
                if "invalid argument" in error_details.lower():
                     return {"error_type": "BadRequest"}, error_msg
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Name.com API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e: 
            self.logger.error(f"Name.com API JSON decode error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}")
            return None, f"API JSON Decode Error: {e}"

    def _get_record_info(self, owner_val, record_type_filter):
        """특정 레코드의 ID와 현재 IP 조회 (Go의 getRecordID 참조)."""
        self.logger.debug(f"Name.com: Getting record info for owner '{owner_val}' on domain '{self.domain}' (type: {record_type_filter})")
        endpoint_path = f"/domains/{self.domain}/records"
        # Name.com API는 GET /records에 필터링 파라미터가 있는지 확인 필요.
        # Go 코드는 모든 레코드를 가져와서 클라이언트 측에서 필터링.
        
        data, error_msg = self._make_api_request("GET", endpoint_path)
        if error_msg:
            # 404는 도메인 자체가 없을 수 있음 (Go 코드의 ErrDomainNotFound)
            if isinstance(data, dict) and data.get("error_type") == "RecordNotFound": # 또는 DomainNotFound
                 self.logger.info(f"Name.com: Domain '{self.domain}' not found or no records for it.")
                 return None, None, False, "Domain not found or no records." # record_id, current_ip, record_exists, error_message
            return None, None, False, error_msg
        
        if data and 'records' in data and isinstance(data['records'], list):
            records_list = data['records']
            for record_entry in records_list:
                if isinstance(record_entry, dict):
                    # Name.com API는 host가 비어있으면 루트 도메인(@)을 의미.
                    host_from_api = record_entry.get('host', '')
                    if host_from_api == '': host_from_api = '@'
                    
                    if (record_entry.get('type') == record_type_filter and
                        host_from_api == owner_val):
                        
                        record_id = record_entry.get('id')
                        current_ip = record_entry.get('answer') # Name.com은 'answer' 필드에 IP 저장
                        if record_id and isinstance(record_id, int):
                            self.logger.info(f"Name.com: Found RecordId: {record_id} for owner '{owner_val}' with IP: {current_ip}")
                            return record_id, current_ip, True, None
            
            self.logger.info(f"Name.com: No existing record found for owner '{owner_val}' (type: {record_type_filter}) on domain '{self.domain}'.")
            return None, None, False, None # 레코드 없음
        else:
            msg = f"Name.com: Unexpected response format when listing records for domain '{self.domain}'. Response: {data}"
            self.logger.error(msg)
            return None, None, False, msg


    def _create_dns_record(self, owner_val, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"Name.com: Creating new {record_type} record for owner '{owner_val}' on domain '{self.domain}' with IP {ip_address}")
        endpoint_path = f"/domains/{self.domain}/records"
        
        payload = {
            "host": owner_val if owner_val != '@' else "", # API는 @ 대신 빈 문자열 기대 가능성
            "type": record_type,
            "answer": ip_address,
        }
        if self.ttl is not None:
            payload["ttl"] = self.ttl

        data, error_msg = self._make_api_request("POST", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        # 성공 시 응답 본문 검증 (Go 코드의 verifySuccessResponseBody)
        verify_ok, verify_msg = self._verify_success_response_body(json.dumps(data) if data else "", ip_address)
        if verify_ok:
            created_id = data.get('id', 'N/A') if isinstance(data, dict) else 'N/A'
            return True, f"Record created successfully (ID: {created_id}). {verify_msg}"
        else:
            return False, f"Record creation API call succeeded, but response verification failed: {verify_msg}"


    def _update_existing_record(self, record_id, owner_val, record_type, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        self.logger.info(f"Name.com: Updating RecordId {record_id} (owner '{owner_val}', type {record_type}) on domain '{self.domain}' to IP {ip_address}")
        
        endpoint_path = f"/domains/{self.domain}/records/{record_id}"
        payload = {
            "host": owner_val if owner_val != '@' else "",
            "type": record_type, # 업데이트 시 type도 보내야 할 수 있음 (API 문서 확인)
            "answer": ip_address,
        }
        if self.ttl is not None:
            payload["ttl"] = self.ttl

        data, error_msg = self._make_api_request("PUT", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        verify_ok, verify_msg = self._verify_success_response_body(json.dumps(data) if data else "", ip_address)
        if verify_ok:
            return True, f"Record updated successfully (ID: {record_id}). {verify_msg}"
        else:
            return False, f"Record update API call succeeded, but response verification failed: {verify_msg}"


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"Name.com: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        # 1. 기존 레코드 정보 (ID 및 현재 IP) 조회
        record_id, current_ip, record_exists, error_msg = self._get_record_info(owner_val, record_type)
        
        if error_msg: # 조회 중 심각한 오류 발생 (도메인 없음 등)
            # RecordNotFound는 _get_record_info에서 record_exists=False, error_msg=None으로 처리됨
            if isinstance(record_id, dict) and record_id.get("error_type") == "RecordNotFound": # getRecordID에서 ErrRecordNotFound 반환 시
                 pass # 아래 record_exists에서 처리
            else:
                 return False, f"Failed to get existing record info: {error_msg}"
        
        if not record_exists:
            self.logger.info(f"Name.com: Record for owner '{owner_val}' (type: {record_type}) not found. Creating new one.")
            create_success, create_msg = self._create_dns_record(owner_val, record_type, ip_address)
            return create_success, create_msg
        
        # 레코드 존재
        if current_ip == ip_address:
            # TTL 등 다른 속성도 같은지 확인하는 로직 추가 가능
            msg = f"Name.com: IP address {ip_address} for owner '{owner_val}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        self.logger.info(f"Name.com: Record ID {record_id} for owner '{owner_val}' ({record_type}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
        update_success, update_msg = self._update_existing_record(record_id, owner_val, record_type, ip_address)
        return update_success, update_msg
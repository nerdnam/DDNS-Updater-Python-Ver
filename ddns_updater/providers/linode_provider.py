# ddns_updater/providers/linode_provider.py
import json
import requests

from .base_provider import BaseProvider

class LinodeProvider(BaseProvider):
    NAME = "linode"
    API_BASE_URL = "https://api.linode.com/v4"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('linode_token')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' # Linode는 name 필드에 owner(@, www)를 사용
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (linode_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 Linode에서 레코드의 name 필드에 사용됨.
        return ["linode_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Linode API는 레코드 생성/수정 시 TTL, priority, weight, port, tag 등을 지원.
        # 필요시 이들을 optional_fields로 추가하고 update_record에서 사용 가능.
        # Go 코드는 TTL 등을 다루지 않음.
        return {"ttl": None} # 예시, 실제 지원 여부 및 기본값 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on Linode using their API (v4)."

    def _build_headers(self, method="GET", filter_header=None):
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.token}'
        }
        if method.upper() in ["POST", "PUT"]:
            headers['Content-Type'] = 'application/json'
        
        # Go 코드의 SetOauth는 특정 스코프를 의미할 수 있음. Linode 문서 확인.
        # 예: headers['X-OAuth-Scopes'] = 'domains:read_write'
        
        if filter_header:
            headers['X-Filter'] = json.dumps(filter_header) # X-Filter 값은 JSON 문자열이어야 함
        return headers

    def _parse_linode_error(self, response_content_str):
        """Linode API 오류 응답 파싱 (Go의 getErrorMessage 참조)"""
        try:
            error_data = json.loads(response_content_str)
            errors_list = error_data.get("errors", [])
            messages = []
            if isinstance(errors_list, list):
                for err_item in errors_list:
                    if isinstance(err_item, dict):
                        field = err_item.get('field', '')
                        reason = err_item.get('reason', '')
                        if field and reason:
                            messages.append(f"Field '{field}': {reason}")
                        elif reason:
                            messages.append(reason)
            return "; ".join(messages) if messages else response_content_str
        except json.JSONDecodeError:
            return response_content_str

    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None, filter_header_val=None):
        """Linode API 요청 실행"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = self._build_headers(method=method, filter_header=filter_header_val)
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=json_payload, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=json_payload, headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method for Linode: {method}")
                return None, f"Unsupported HTTP method: {method}"

            response_content_str = response.text 

            if 200 <= response.status_code < 300:
                if not response_content_str and response.status_code in [200, 204]:
                    return {}, None 
                return response.json(), None
            else: 
                error_details = self._parse_linode_error(response_content_str)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                self.logger.error(f"Linode API call to {method} {url} failed. {error_msg}")
                if response.status_code == 404:
                    return {"error_type": "NotFound"}, error_msg
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Linode API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            self.logger.error(f"Linode API JSON decode error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}")
            return None, f"API JSON Decode Error: {e}"

    def _get_domain_id(self):
        """설정된 domain에 해당하는 Domain ID 조회 (Go의 getDomainID 참조)"""
        self.logger.debug(f"Linode: Getting Domain ID for domain '{self.domain}'")
        endpoint_path = "/domains"
        # X-Filter 헤더를 사용하여 도메인 이름으로 필터링
        filter_val = {"domain": self.domain}
        
        data, error_msg = self._make_api_request("GET", endpoint_path, filter_header_val=filter_val)
        if error_msg:
            return None, error_msg
        
        if data and 'data' in data and isinstance(data['data'], list):
            domains_list = data['data']
            if len(domains_list) == 1:
                domain_entry = domains_list[0]
                domain_id = domain_entry.get('id')
                status = domain_entry.get('status')
                if status == "disabled":
                    msg = f"Linode: Domain '{self.domain}' is disabled."
                    self.logger.error(msg)
                    return None, msg
                if domain_id and isinstance(domain_id, int):
                    self.logger.info(f"Linode: Found Domain ID: {domain_id} for domain '{self.domain}' (status: {status})")
                    return domain_id, None
                else: # ID가 없거나 유효하지 않음
                    msg = f"Linode: Domain ID not found or invalid in response for '{self.domain}'."
                    self.logger.error(msg)
                    return None, msg
            elif len(domains_list) == 0:
                msg = f"Linode: Domain '{self.domain}' not found."
                self.logger.error(msg)
                return None, msg
            else: # 여러 도메인 반환 (필터가 정확히 동작 안 했거나 중복 도메인)
                msg = f"Linode: Multiple domains found for filter '{self.domain}'. Expected 1, got {len(domains_list)}."
                self.logger.error(msg)
                return None, msg
        else:
            msg = f"Linode: Unexpected response format when getting domain ID. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _get_record_info(self, domain_id, owner_val, record_type_filter):
        """특정 Domain ID 내에서 owner와 type이 일치하는 레코드 ID와 현재 IP 조회 (Go의 getRecordID 참조)."""
        self.logger.debug(f"Linode: Getting record info for owner '{owner_val}' (type: {record_type_filter}) in domain ID {domain_id}")
        endpoint_path = f"/domains/{domain_id}/records"
        # Linode는 GET /records에 name, type 필터링 파라미터가 있는지 확인 필요.
        # Go 코드는 모든 레코드를 가져와서 클라이언트 측에서 필터링.
        
        data, error_msg = self._make_api_request("GET", endpoint_path)
        if error_msg:
            return None, None, False, error_msg # record_id, current_ip, record_exists, error_message
        
        if data and 'data' in data and isinstance(data['data'], list):
            records_list = data['data']
            for record_entry in records_list:
                if (isinstance(record_entry, dict) and
                    record_entry.get('type') == record_type_filter and
                    record_entry.get('name') == owner_val): # Linode는 'name' 필드에 owner (@, www) 사용
                    
                    record_id = record_entry.get('id')
                    current_ip = record_entry.get('target') # Linode는 'target' 필드에 IP 저장
                    if record_id and isinstance(record_id, int):
                        self.logger.info(f"Linode: Found RecordId: {record_id} for owner '{owner_val}' with IP: {current_ip}")
                        return record_id, current_ip, True, None
            
            # 일치하는 레코드 없음
            self.logger.info(f"Linode: No existing record found for owner '{owner_val}' (type: {record_type_filter}) in domain ID {domain_id}.")
            return None, None, False, None
        else:
            msg = f"Linode: Unexpected response format when listing records for domain ID {domain_id}. Response: {data}"
            self.logger.error(msg)
            return None, None, False, msg


    def _create_dns_record(self, domain_id, owner_val, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        # Linode API는 'name' 필드에 owner(@, www)를, 'target' 필드에 IP를 사용.
        # 'type'은 A 또는 AAAA.
        # Go 코드에서는 createRecord의 requestData.Host에 FQDN을 사용했는데,
        # Linode API 문서를 보면 POST /domains/{id}/records 의 'name'은 호스트 부분만.
        # 여기서는 owner_val (호스트 부분)을 사용.
        self.logger.info(f"Linode: Creating new {record_type} record for owner '{owner_val}' in domain ID {domain_id} with IP {ip_address}")
        endpoint_path = f"/domains/{domain_id}/records"
        
        payload = {
            "type": record_type,
            "name": owner_val, # owner (@, www 등)
            "target": ip_address,
            # "ttl_sec": self.config.get('ttl', 300) # Linode는 ttl_sec 사용, Go 코드는 TTL 미사용
        }
        # Linode API는 TTL을 ttl_sec으로 받음. 기본값은 도메인의 기본 TTL.
        # 필요시 self.config.get('linode_ttl') 등으로 설정 가능하게 하고 payload에 추가.

        data, error_msg = self._make_api_request("POST", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        if data and 'id' in data: # 생성 성공 시 응답에 생성된 레코드 정보 포함
            created_record = data
            created_ip = created_record.get('target')
            created_id = created_record.get('id')
            if created_ip != ip_address:
                msg = f"Linode: Record created (ID: {created_id}), but created IP ({created_ip}) does not match target IP ({ip_address})."
                self.logger.error(msg)
                return False, msg
                
            self.logger.info(f"Linode: Successfully created record. New RecordId: {created_id}, IP: {created_ip}")
            return True, f"Record created successfully (ID: {created_id})."
        else:
            msg = f"Linode: Failed to create record or no ID/target in response. Response: {data}"
            self.logger.error(msg)
            return False, msg


    def _update_existing_record(self, domain_id, record_id, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        self.logger.info(f"Linode: Updating RecordId {record_id} in domain ID {domain_id} to IP {ip_address}")
        
        endpoint_path = f"/domains/{domain_id}/records/{record_id}"
        # Linode API는 PUT /records/{id} 요청 시 'target' 필드만 변경 가능.
        # 다른 필드(type, name, ttl_sec)는 변경 불가.
        payload = {
            "target": ip_address
            # "ttl_sec": self.config.get('ttl', 300) # TTL도 업데이트하려면 추가
        }

        data, error_msg = self._make_api_request("PUT", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        if data and 'id' in data: # 업데이트 성공 시 응답에 업데이트된 레코드 정보 포함
            updated_record = data
            updated_ip = updated_record.get('target')
            if updated_ip == ip_address:
                self.logger.info(f"Linode: Successfully updated RecordId {record_id}. IP confirmed: {updated_ip}")
                return True, f"Record updated successfully (ID: {record_id})."
            else:
                msg = f"Linode: Successfully updated RecordId {record_id}, but API returned IP '{updated_ip}' instead of '{ip_address}'."
                self.logger.warning(msg)
                return True, msg # 일단 성공으로 처리하나 경고
        else:
            msg = f"Linode: Failed to update record or unexpected response format. Response: {data}"
            self.logger.error(msg)
            return False, msg


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        # 1. Domain ID 가져오기
        domain_id, error_msg = self._get_domain_id()
        if error_msg or not domain_id:
            return False, f"Failed to get Domain ID for '{self.domain}': {error_msg or 'Domain ID not found.'}"

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"Linode: Attempting to update owner '{owner_val}' on domain '{self.domain}' (ID: {domain_id}, type: {record_type}) to IP: {ip_address}")

        # 2. 기존 레코드 정보 (ID 및 현재 IP) 조회
        record_id, current_ip, record_exists, error_msg = self._get_record_info(domain_id, owner_val, record_type)
        
        if error_msg: # 조회 중 심각한 오류 발생
            return False, f"Failed to get existing record info: {error_msg}"
        
        if not record_exists:
            self.logger.info(f"Linode: Record for owner '{owner_val}' (type: {record_type}) not found. Creating new one.")
            create_success, create_msg = self._create_dns_record(domain_id, owner_val, record_type, ip_address)
            return create_success, create_msg
        
        # 레코드 존재
        if current_ip == ip_address:
            # TTL 등 다른 속성도 같은지 확인하는 로직 추가 가능
            msg = f"Linode: IP address {ip_address} for owner '{owner_val}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        self.logger.info(f"Linode: Record ID {record_id} for owner '{owner_val}' ({record_type}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
        update_success, update_msg = self._update_existing_record(domain_id, record_id, ip_address)
        return update_success, update_msg
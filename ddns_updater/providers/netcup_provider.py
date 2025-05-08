# ddns_updater/providers/netcup_provider.py
import json
import requests

from .base_provider import BaseProvider

class NetcupProvider(BaseProvider):
    NAME = "netcup"
    API_ENDPOINT = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON"
    # Netcup API는 TTL을 직접 설정하는 파라미터가 updateDnsRecords에 없는 것으로 보임.
    # infoDnsRecords 응답에도 TTL이 없음. Zone의 기본 TTL을 따를 가능성.

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.customer_number = self.config.get('netcup_customer_number')
        self.api_key = self.config.get('netcup_api_key')
        self.api_password = self.config.get('netcup_api_password')
        
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' # Netcup은 hostname 필드에 owner(@, www)를 사용
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.customer_number, self.api_key, self.api_password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (customer_number, api_key, api_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        self.api_session_id = None # 로그인 후 채워짐

    @staticmethod
    def get_required_config_fields():
        # owner는 Netcup에서 hostname 필드에 사용됨.
        return ["netcup_customer_number", "netcup_api_key", "netcup_api_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Netcup API가 TTL을 직접 제어하는지 확인 필요.
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Netcup using their CCP API."

    def _parse_netcup_error(self, response_data, http_status_code=None):
        """Netcup API 오류 응답 파싱"""
        if isinstance(response_data, dict):
            status = response_data.get('status', 'unknown_status')
            status_code_api = response_data.get('statuscode', http_status_code or 'N/A')
            short_message = response_data.get('shortmessage', 'No specific error message from API.')
            # long_message = response_data.get('longmessage', '') # 필요시 사용
            return f"Status: {status} (Code: {status_code_api}), Message: {short_message}"
        elif isinstance(response_data, str): # JSON 파싱 실패 시 문자열일 수 있음
            return response_data
        return "Unknown error format."


    def _make_api_request(self, action, params_dict):
        """Netcup API 요청 실행 (항상 POST, JSON)"""
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        # 요청 본문 구성
        request_payload = {
            "action": action,
            "param": params_dict
        }
        self.logger.debug(f"Netcup API Request to action '{action}', params: {params_dict}")

        try:
            response = requests.post(self.API_ENDPOINT, json=request_payload, headers=headers, timeout=timeout)
            response_content_str = response.text # 오류 파싱 및 디버깅용
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                self.logger.error(f"Netcup API JSON decode error. Status: {response.status_code}, Body: '{response_content_str}'")
                return None, f"API JSON Decode Error: Failed to parse response. HTTP Status: {response.status_code}"

            self.logger.debug(f"Netcup API Response for action '{action}', Status: {response.status_code}, Full Body: {data}")

            # Netcup API는 HTTP 상태 코드 200을 반환하고, 내부 status 필드로 성공/실패 알림
            if response.status_code == 200 and isinstance(data, dict) and data.get('status') == 'success':
                return data.get('responsedata'), None # 성공 시 'responsedata' 반환
            else: 
                error_details = self._parse_netcup_error(data, response.status_code)
                error_msg = f"API Error: {error_details}"
                # HTTP 상태 코드가 200이 아니거나, 200이지만 내부 status가 'error'인 경우
                if response.status_code != 200:
                     error_msg = f"API HTTP Error {response.status_code}: {error_details}"
                
                self.logger.error(f"Netcup API call to action '{action}' failed. {error_msg}")
                # 특정 오류 코드에 따른 예외 매핑 가능
                if data.get('statuscode') == 2011: # 예: Invalid session ID
                    return {"error_type": "AuthError"}, error_msg # 세션 만료 등
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Netcup API request failed: {e}")
            return None, f"API Request Error: {e}"

    def _login(self):
        """Netcup API 로그인 및 세션 ID 획득"""
        if self.api_session_id: # 이미 유효한 세션이 있다고 가정 (실제로는 만료 시간 고려 필요)
            self.logger.debug("Using existing Netcup API session ID.")
            return self.api_session_id, None
            
        self.logger.info("Netcup: Attempting to login and get session ID...")
        params = {
            "apikey": self.api_key,
            "apipassword": self.api_password,
            "customernumber": self.customer_number
        }
        response_data, error_msg = self._make_api_request("login", params)
        if error_msg:
            return None, f"Login failed: {error_msg}"
        
        if response_data and isinstance(response_data, dict) and 'apisessionid' in response_data:
            self.api_session_id = response_data['apisessionid']
            if not self.api_session_id: # 세션 ID가 비어있는 경우
                 return None, "Login successful but API session ID is empty."
            self.logger.info("Netcup: Login successful, session ID obtained.")
            return self.api_session_id, None
        else:
            return None, f"Login failed: 'apisessionid' not found in response. Response: {response_data}"

    def _list_dns_records(self, session_id):
        """특정 도메인의 모든 DNS 레코드 조회 (Go의 infoDNSRecords 참조)"""
        self.logger.debug(f"Netcup: Listing DNS records for domain '{self.domain}' with session ID.")
        params = {
            "apikey": self.api_key, # 로그인 후에도 API Key/Session ID/Customer No.는 계속 필요
            "apisessionid": session_id,
            "customernumber": self.customer_number,
            "domainname": self.domain
        }
        response_data, error_msg = self._make_api_request("infoDnsRecords", params)
        if error_msg:
            return None, error_msg
        
        if response_data and isinstance(response_data, dict) and 'dnsrecords' in response_data:
            return response_data['dnsrecords'], None # 레코드 리스트 반환
        else:
            return [], None # 레코드가 없거나 응답 형식이 다르면 빈 리스트 (또는 오류)

    def _update_dns_records_in_set(self, session_id, records_to_update_list):
        """DNS 레코드 세트 업데이트/생성 (Go의 updateDNSRecords 참조)"""
        # records_to_update_list는 [dnsRecord_dict1, dnsRecord_dict2, ...] 형태
        self.logger.info(f"Netcup: Updating DNS records for domain '{self.domain}' with {len(records_to_update_list)} record(s).")
        self.logger.debug(f"Records to update/create: {records_to_update_list}")

        dns_record_set_payload = {"dnsrecords": records_to_update_list}
        params = {
            "apikey": self.api_key,
            "apisessionid": session_id,
            "customernumber": self.customer_number,
            "domainname": self.domain,
            "dnsrecordset": dns_record_set_payload
        }
        
        response_data, error_msg = self._make_api_request("updateDnsRecords", params)
        if error_msg:
            return None, error_msg # 업데이트된 레코드 세트 또는 오류 메시지
        
        # 성공 시 응답에도 업데이트된 레코드 세트가 포함됨
        if response_data and isinstance(response_data, dict) and 'dnsrecords' in response_data:
            return response_data['dnsrecords'], None
        else:
            return None, f"Update successful but no 'dnsrecords' in response. Response: {response_data}"


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        # 1. 로그인하여 세션 ID 획득
        session_id, error_msg = self._login()
        if error_msg or not session_id:
            return False, f"Netcup login failed: {error_msg or 'Could not obtain session ID.'}"

        # 2. 현재 DNS 레코드 목록 조회
        owner_val = self.config.get('owner', '@')
        self.logger.info(f"Netcup: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        current_records, error_msg = self._list_dns_records(session_id)
        if error_msg:
            return False, f"Failed to list existing DNS records: {error_msg}"

        record_to_update_or_create = None
        existing_record_found = False

        if isinstance(current_records, list):
            for record in current_records:
                if (isinstance(record, dict) and
                    record.get('hostname') == owner_val and
                    record.get('type') == record_type):
                    
                    existing_record_found = True
                    current_ip = record.get('destination')
                    if current_ip == ip_address:
                        msg = f"Netcup: IP address {ip_address} for owner '{owner_val}' is already up to date."
                        self.logger.info(msg)
                        return True, msg
                    
                    # IP가 다르면 이 레코드를 업데이트 대상으로 설정
                    record_to_update_or_create = record.copy() # 기존 레코드 복사
                    record_to_update_or_create['destination'] = ip_address
                    # Netcup API는 ID를 보내면 수정, ID 없으면 생성으로 동작할 수 있음.
                    # Go 코드는 ID를 유지. 여기서는 ID를 유지하여 업데이트 시도.
                    # TTL, Priority 등 다른 필드는 기존 값 유지 또는 API 기본값.
                    # Netcup API는 updateDnsRecords 시 전체 레코드 세트를 보내야 함.
                    # 여기서는 해당 레코드만 수정하여 전체 세트에 포함시켜 보냄.
                    break # 첫 번째 매칭 레코드만 처리 (일반적인 DDNS 시나리오)
        
        if not existing_record_found:
            self.logger.info(f"Netcup: Record for owner '{owner_val}' (type: {record_type}) not found. Preparing to create new one.")
            # 새 레코드 생성 정보 준비 (ID는 없음)
            record_to_update_or_create = {
                "hostname": owner_val,
                "type": record_type,
                "destination": ip_address,
                # "priority": "0", # A/AAAA는 보통 0 또는 불필요
                # "state": "yes" # 활성화 상태, API 기본값 따를 수 있음
            }
        
        if record_to_update_or_create is None: # IP가 같아서 업데이트 불필요한 경우 이미 반환됨
             return False, "Logic error: record_to_update_or_create should have been set."


        # 3. DNS 레코드 업데이트/생성
        # Netcup API는 updateDnsRecords로 전체 레코드 세트를 전달.
        # 수정할 레코드만 변경하고, 나머지 레코드는 그대로 유지하여 전체를 보내야 함.
        final_record_set_to_send = []
        updated_flag = False
        if isinstance(current_records, list):
            for rec in current_records:
                if (isinstance(rec, dict) and
                    rec.get('hostname') == owner_val and
                    rec.get('type') == record_type):
                    # 위에서 찾은 업데이트 대상 레코드 (또는 생성 대상 정보)
                    final_record_set_to_send.append(record_to_update_or_create)
                    updated_flag = True
                else: # 다른 레코드들은 그대로 추가
                    final_record_set_to_send.append(rec.copy())
        
        if not updated_flag: # 기존 레코드 목록에 없었고, 새로 추가해야 하는 경우
            final_record_set_to_send.append(record_to_update_or_create)

        updated_records_response, error_msg = self._update_dns_records_in_set(session_id, final_record_set_to_send)
        
        if error_msg:
            return False, f"Failed to update/create DNS record: {error_msg}"

        # 4. 업데이트 결과 확인 (선택적이지만 권장)
        if updated_records_response and isinstance(updated_records_response, list):
            for updated_rec in updated_records_response:
                if (isinstance(updated_rec, dict) and
                    updated_rec.get('hostname') == owner_val and
                    updated_rec.get('type') == record_type and
                    updated_rec.get('destination') == ip_address):
                    self.logger.info(f"Netcup: Successfully updated/created record for owner '{owner_val}'. IP confirmed: {ip_address}")
                    return True, f"Record for {owner_val} updated/created successfully to {ip_address}."
            
            # 응답에 해당 레코드가 없거나 IP가 다르면 문제
            msg = f"Netcup: Update API call succeeded, but verification of updated record failed. Expected IP: {ip_address}, Response records: {updated_records_response}"
            self.logger.error(msg)
            return False, msg
        else:
            # 업데이트는 성공했으나 응답에서 확인 불가
            msg = f"Netcup: Update API call reported success, but could not verify from response. Assuming success for {owner_val} to {ip_address}."
            self.logger.warning(msg)
            return True, msg # 일단 성공으로 처리
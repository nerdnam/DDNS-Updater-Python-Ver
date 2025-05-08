# ddns_updater/providers/ionos_provider.py
import json
import requests
from urllib.parse import quote # API Key에 특수문자 가능성 대비 (보통은 불필요)

from .base_provider import BaseProvider

class IonosProvider(BaseProvider):
    NAME = "ionos"
    API_BASE_URL = "https://api.hosting.ionos.com/dns/v1"
    DEFAULT_TTL = 3600 # Go 코드 기준

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('ionos_api_key')
        # self.domain, self.owner 는 BaseProvider 에서 처리
        
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.api_key, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (ionos_api_key, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if self.config.get('owner') == '*': # Ionos는 와일드카드 레코드를 지원하지만, owner='*'의 의미는 다를 수 있음
            self.logger.warning(f"{self.NAME.capitalize()}: Wildcard owner ('*') might have special meaning or require specific handling with Ionos API.")


    @staticmethod
    def get_required_config_fields():
        # owner는 Ionos에서 recordName 구성에 필요.
        return ["ionos_api_key", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # Ionos API는 TTL, Prio, Disabled 등을 지원.
        return {"ttl": IonosProvider.DEFAULT_TTL} 

    @staticmethod
    def get_description():
        return "Updates DNS records on Ionos (1&1) using their DNS API (v1)."

    def _build_headers(self, include_content_type=False):
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Accept': 'application/json',
            'X-API-Key': self.api_key
        }
        if include_content_type:
            headers['Content-Type'] = 'application/json'
        return headers

    def _parse_ionos_error(self, response_content_str):
        """Ionos API 오류 응답 파싱 (Go의 decodeErrorMessage 참조)"""
        try:
            errors_list = json.loads(response_content_str) # Ionos 오류는 보통 JSON 배열
            messages = []
            if isinstance(errors_list, list):
                for err_item in errors_list:
                    if isinstance(err_item, dict):
                        msg = err_item.get('message', '')
                        code = err_item.get('code', '')
                        if msg and code:
                            messages.append(f"Code: {code}, Message: {msg}")
                        elif msg:
                            messages.append(msg)
                        elif code:
                            messages.append(f"Code: {code}")
            return "; ".join(messages) if messages else response_content_str
        except json.JSONDecodeError:
            return response_content_str

    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None):
        """Ionos DNS API 요청 실행"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        is_post_put = method.upper() in ["POST", "PUT"]
        headers = self._build_headers(include_content_type=is_post_put)
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=json_payload, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=json_payload, headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method for Ionos: {method}")
                return None, f"Unsupported HTTP method: {method}"

            response_content_str = response.text 

            # Ionos API는 성공 시 200 OK (GET, PUT) 또는 201 Created (POST) 반환
            if method.upper() == "POST" and response.status_code == 201: # 생성 성공
                 # POST 성공 시 응답 본문은 생성된 리소스 ID 배열일 수 있음
                 try: return response.json() if response_content_str else {}, None
                 except json.JSONDecodeError: return {}, None # 본문 없거나 JSON 아니면 빈 객체
            elif method.upper() != "POST" and response.status_code == 200: # 조회/수정 성공
                 try: return response.json() if response_content_str else {}, None
                 except json.JSONDecodeError: return {}, None
            else: # 오류 발생
                error_details = self._parse_ionos_error(response_content_str)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                self.logger.error(f"Ionos API call to {method} {url} failed. {error_msg}")
                # 특정 상태 코드에 따른 예외 매핑
                if response.status_code == 401: # Unauthorized
                    return {"error_type": "AuthError"}, error_msg
                if response.status_code == 404: # Not Found
                    return {"error_type": "NotFoundError"}, error_msg
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ionos API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e: # 성공 응답 후 JSON 파싱 실패 (거의 없을 듯)
            self.logger.error(f"Ionos API JSON decode error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}")
            return None, f"API JSON Decode Error: {e}"

    def _get_zone_id(self):
        """설정된 domain에 해당하는 Zone ID 조회 (Go의 getZones 참조)"""
        self.logger.debug(f"Ionos: Getting Zone ID for domain '{self.domain}'")
        endpoint_path = "/zones"
        # Ionos API는 zoneName으로 필터링하는 파라미터가 있는지 확인 필요.
        # 없다면 모든 zone을 가져와서 필터링.
        # Go 코드는 모든 zone을 가져와서 루프를 돌며 p.domain과 일치하는 것을 찾음.
        
        data, error_msg = self._make_api_request("GET", endpoint_path)
        if error_msg:
            return None, error_msg
        
        if isinstance(data, list): # 응답이 zone 객체 배열
            for zone in data:
                if isinstance(zone, dict) and zone.get('name') == self.domain:
                    zone_id = zone.get('id')
                    if zone_id:
                        self.logger.info(f"Ionos: Found Zone ID: {zone_id} for domain '{self.domain}'")
                        return zone_id, None
            # 일치하는 zone 없음
            msg = f"Ionos: Zone for domain '{self.domain}' not found among {len(data)} zones."
            self.logger.error(msg)
            return None, msg
        else:
            msg = f"Ionos: Unexpected response format when getting zones. Expected list, got {type(data)}. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _list_records_in_zone(self, zone_id, record_name_filter, record_type_filter):
        """특정 Zone 내에서 FQDN과 타입이 일치하는 레코드 목록 조회 (Go의 getRecords 참조)"""
        self.logger.debug(f"Ionos: Listing records in zone '{zone_id}' for name '{record_name_filter}' (type: {record_type_filter})")
        endpoint_path = f"/zones/{zone_id}/records"
        params = {
            'recordName': record_name_filter, # FQDN
            'recordType': record_type_filter
        }
        
        data, error_msg = self._make_api_request("GET", endpoint_path, query_params=params)
        if error_msg:
            return None, error_msg
        
        # Ionos API는 /records 엔드포인트에서 'records' 키 없이 바로 레코드 배열을 반환할 수 있음.
        # Go 코드에서는 responseData.Records 로 접근.
        if isinstance(data, list): # 응답이 레코드 객체 배열
            return data, None
        elif isinstance(data, dict) and 'records' in data and isinstance(data['records'], list): # 또는 'records' 키 아래 배열
            return data['records'], None
        else:
            msg = f"Ionos: Unexpected response format when listing records. Expected list or dict with 'records' list. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _create_dns_record(self, zone_id, fqdn, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"Ionos: Creating new {record_type} record for {fqdn} in zone '{zone_id}' with IP {ip_address}")
        endpoint_path = f"/zones/{zone_id}/records"
        
        # Ionos API는 레코드 생성 시 배열 형태의 페이로드를 기대.
        payload_list = [{
            "name": fqdn, # FQDN
            "type": record_type,
            "content": ip_address,
            "ttl": self.config.get('ttl', self.DEFAULT_TTL), # 설정된 TTL 또는 기본값
            "prio": 0, # A/AAAA 레코드에는 보통 0
            "disabled": False
        }]

        data, error_msg = self._make_api_request("POST", endpoint_path, json_payload=payload_list)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        # POST 성공 시 (201 Created), 응답 본문은 생성된 리소스 ID 배열일 수 있음.
        # Go 코드는 본문을 확인하지 않고 성공으로 간주.
        # 여기서는 data가 비어있지 않으면 성공으로 간주.
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and data[0].get('id'):
             created_id = data[0]['id']
             self.logger.info(f"Ionos: Successfully created record. New Record ID (from list): {created_id}")
             return True, f"Record created successfully (ID: {created_id})."
        elif isinstance(data, dict) and data.get('id'): # 단일 객체로 반환될 수도 있음
             created_id = data['id']
             self.logger.info(f"Ionos: Successfully created record. New Record ID (from dict): {created_id}")
             return True, f"Record created successfully (ID: {created_id})."
        else: # 성공했으나 ID 확인 불가
             self.logger.info(f"Ionos: Record creation reported success (201 Created), but could not verify record ID from response: {data}")
             return True, "Record creation reported success (201 Created)."


    def _update_existing_record(self, zone_id, record_id, existing_record_data, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        fqdn = existing_record_data.get('name')
        record_type = existing_record_data.get('type')
        self.logger.info(f"Ionos: Updating RecordId {record_id} ({fqdn}, type {record_type}) in zone '{zone_id}' to IP {ip_address}")
        
        endpoint_path = f"/zones/{zone_id}/records/{record_id}"
        payload = {
            "content": ip_address,
            # 기존 레코드의 다른 값들은 유지 (Go 코드 참조)
            "ttl": existing_record_data.get('ttl', self.config.get('ttl', self.DEFAULT_TTL)),
            "prio": existing_record_data.get('prio', 0),
            "disabled": existing_record_data.get('disabled', False),
            # name, type은 PUT 요청 시 필요 없을 수 있음 (URL에 포함되므로). API 문서 확인.
            # 하지만 안전하게 포함하는 것이 좋을 수 있음.
            "name": fqdn,
            "type": record_type,
        }

        data, error_msg = self._make_api_request("PUT", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        # PUT 성공 시 (200 OK), 응답 본문은 업데이트된 리소스 객체일 수 있음.
        # Go 코드는 본문을 확인하지 않고 성공으로 간주.
        if isinstance(data, dict) and data.get('id') == record_id and data.get('content') == ip_address:
            self.logger.info(f"Ionos: Successfully updated RecordId {record_id}. IP confirmed: {data['content']}")
            return True, f"Record updated successfully (ID: {record_id})."
        else: # 성공했으나 확인 불가 또는 IP 불일치
            self.logger.info(f"Ionos: Record update reported success (200 OK), but response verification failed or IP mismatch. Response: {data}")
            return True, "Record update reported success (200 OK)."


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        # 1. Zone ID 가져오기
        zone_id, error_msg = self._get_zone_id()
        if error_msg or not zone_id:
            return False, f"Failed to get Zone ID for domain '{self.domain}': {error_msg or 'Zone not found.'}"

        # 2. 업데이트할 FQDN 구성
        owner_val = self.config.get('owner', '@')
        # Ionos API는 recordName에 FQDN을 기대.
        fqdn_to_update = self.domain
        if owner_val != '@' and owner_val != '':
            fqdn_to_update = f"{owner_val}.{self.domain}"
        
        self.logger.info(f"Ionos: Attempting to update {fqdn_to_update} ({record_type}) in zone '{zone_id}' to IP: {ip_address}")

        # 3. 기존 레코드 목록 조회
        records, error_msg = self._list_records_in_zone(zone_id, fqdn_to_update, record_type)
        if error_msg:
            # 404 (NotFoundError)는 레코드가 없는 경우일 수 있음. create로 진행.
            if isinstance(records, dict) and records.get("error_type") == "NotFoundError":
                 self.logger.info(f"Ionos: No existing record found for {fqdn_to_update} ({record_type}). Creating new one.")
                 create_success, create_msg = self._create_dns_record(zone_id, fqdn_to_update, record_type, ip_address)
                 return create_success, create_msg
            return False, f"Failed to list existing records: {error_msg}"

        matching_records = []
        if records: # records가 None이 아니고 비어있지 않은 리스트일 때
            for record in records:
                if isinstance(record, dict) and record.get('name') == fqdn_to_update and record.get('type') == record_type:
                    matching_records.append(record)
        
        if not matching_records: # 일치하는 레코드 없음
            self.logger.info(f"Ionos: No specific record found for {fqdn_to_update} ({record_type}) after listing. Creating new one.")
            create_success, create_msg = self._create_dns_record(zone_id, fqdn_to_update, record_type, ip_address)
            return create_success, create_msg

        # 일치하는 레코드 처리 (Go 코드는 여러 개일 경우 모두 업데이트 시도)
        all_updates_successful = True
        final_messages = []

        for record_data in matching_records:
            record_id = record_data.get('id')
            current_ip = record_data.get('content')

            if not record_id:
                self.logger.warning(f"Ionos: Found matching record for {fqdn_to_update} but it has no ID. Skipping. Data: {record_data}")
                final_messages.append(f"Skipped record with no ID for {fqdn_to_update}.")
                all_updates_successful = False # 또는 계속 진행할지 결정
                continue

            if current_ip == ip_address:
                msg = f"Ionos: IP address {ip_address} for record ID {record_id} ({fqdn_to_update}) is already up to date."
                self.logger.info(msg)
                final_messages.append(msg)
                continue # 다음 매칭 레코드로
            
            # IP가 다르면 업데이트
            self.logger.info(f"Ionos: Record ID {record_id} ({fqdn_to_update}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
            update_success, update_msg = self._update_existing_record(zone_id, record_id, record_data, ip_address)
            final_messages.append(update_msg)
            if not update_success:
                all_updates_successful = False
                # 하나의 업데이트라도 실패하면 전체 실패로 간주할 수 있음
                # return False, f"Failed to update record ID {record_id}: {update_msg}" 
        
        return all_updates_successful, "; ".join(final_messages)
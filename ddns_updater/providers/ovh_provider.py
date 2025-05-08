# ddns_updater/providers/ovh_provider.py
import json
import hashlib
import time
import requests
from urllib.parse import quote, urlparse, urlunparse, urlencode

from .base_provider import BaseProvider

class OvhProvider(BaseProvider):
    NAME = "ovh"
    # API 엔드포인트는 설정에 따라 동적으로 결정됨
    # DynHost 엔드포인트
    DYNHOST_API_HOST = "www.ovh.com" # 또는 각 지역별 엔드포인트 (예: www.ovh.ca)
    DYNHOST_API_PATH = "/nic/update"

    # API 엔드포인트 매핑 (Go 코드의 convertShortEndpoint 참조)
    API_ENDPOINT_MAP = {
        "": "https://eu.api.ovh.com/1.0", # 기본값
        "ovh-eu": "https://eu.api.ovh.com/1.0",
        "ovh-ca": "https://ca.api.ovh.com/1.0",
        "ovh-us": "https://api.us.ovhcloud.com/1.0", # Go 코드와 약간 다름, 문서 확인
        "kimsufi-eu": "https://eu.api.kimsufi.com/1.0",
        "kimsufi-ca": "https://ca.api.kimsufi.com/1.0",
        "soyoustart-eu": "https://eu.api.soyoustart.com/1.0",
        "soyoustart-ca": "https://ca.api.soyoustart.com/1.0",
    }


    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.mode = self.config.get('ovh_mode', 'dynhost').lower() # 기본값 'dynhost'

        # DynHost 모드 설정
        self.dynhost_username = self.config.get('ovh_dynhost_username')
        self.dynhost_password = self.config.get('ovh_dynhost_password')

        # API 모드 설정
        self.api_endpoint_short = self.config.get('ovh_api_endpoint', 'ovh-eu') # 기본 'ovh-eu'
        self.app_key = self.config.get('ovh_app_key')
        self.app_secret = self.config.get('ovh_app_secret')
        self.consumer_key = self.config.get('ovh_consumer_key')
        
        self.api_base_url_obj = None
        if self.mode == 'api':
            base_url_str = self.API_ENDPOINT_MAP.get(self.api_endpoint_short.lower())
            if not base_url_str:
                valid_endpoints = ", ".join(self.API_ENDPOINT_MAP.keys())
                error_msg = f"{self.NAME.capitalize()} provider: Invalid 'ovh_api_endpoint' value '{self.api_endpoint_short}'. Valid options are: {valid_endpoints}"
                self.logger.error(error_msg)
                raise ValueError(error_msg)
            try:
                self.api_base_url_obj = urlparse(base_url_str)
            except Exception as e:
                error_msg = f"{self.NAME.capitalize()} provider: Could not parse API base URL from endpoint '{self.api_endpoint_short}': {e}"
                self.logger.error(error_msg)
                raise ValueError(error_msg)

        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인 (모드에 따라 다름)
        if not self.domain:
            error_msg = f"{self.NAME.capitalize()} provider: 'domain' is required."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        if self.mode == 'api':
            if not all([self.app_key, self.app_secret, self.consumer_key, self.api_base_url_obj]):
                error_msg = f"{self.NAME.capitalize()} provider (API mode): 'ovh_app_key', 'ovh_app_secret', 'ovh_consumer_key', and a valid 'ovh_api_endpoint' are required."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
        elif self.mode == 'dynhost':
            if not all([self.dynhost_username, self.dynhost_password]):
                error_msg = f"{self.NAME.capitalize()} provider (DynHost mode): 'ovh_dynhost_username' and 'ovh_dynhost_password' are required."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
            if self.config.get('owner') == '*': # DynHost 모드에서 와일드카드 금지
                error_msg = f"{self.NAME.capitalize()} provider (DynHost mode): Wildcard owner ('*') is not allowed."
                self.logger.error(error_msg)
                raise ValueError(error_msg)
        else:
            error_msg = f"{self.NAME.capitalize()} provider: Invalid 'ovh_mode' value '{self.mode}'. Must be 'api' or 'dynhost'."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        self.server_time_delta = None # API 모드용 시간 차이


    @staticmethod
    def get_required_config_fields():
        # 모드에 따라 달라지므로, 여기서는 공통적인 domain만 명시하고 __init__에서 상세 검증
        return ["domain", "owner", "ovh_mode"] 

    @staticmethod
    def get_optional_config_fields():
        return {
            "ovh_dynhost_username": None,
            "ovh_dynhost_password": None,
            "ovh_api_endpoint": "ovh-eu",
            "ovh_app_key": None,
            "ovh_app_secret": None,
            "ovh_consumer_key": None,
            "ttl": None # API 모드에서 TTL 설정 가능성 (문서 확인)
        }

    @staticmethod
    def get_description():
        return "Updates DNS records on OVH using either DynHost or ZoneDNS API."

    # --- DynHost Mode Methods ---
    def _update_with_dynhost(self, ip_address, record_type):
        hostname_for_query = self._build_fqdn_for_dynhost() # DynHost는 FQDN 사용
        
        self.logger.info(f"{self.NAME.capitalize()} (DynHost): Attempting to update {hostname_for_query} to IP: {ip_address}")

        userinfo_user = quote(self.dynhost_username, safe='')
        userinfo_pass = quote(self.dynhost_password, safe='')
        
        # DynHost 엔드포인트는 지역별로 다를 수 있음 (예: ovh.ca). API_ENDPOINT_MAP과 유사하게 처리 필요.
        # Go 코드는 www.ovh.com으로 고정. 여기서는 일단 따름.
        target_url = f"https://{userinfo_user}:{userinfo_pass}@{self.DYNHOST_API_HOST}{self.DYNHOST_API_PATH}"
        
        params = {
            'system': 'dyndns',
            'hostname': hostname_for_query,
            'myip': ip_address
        }
        
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(target_url, params=params, headers=headers, timeout=timeout)
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} (DynHost) API Response Status: {response.status_code}, Body: '{response_text}'")

            if response.status_code != 200:
                return False, f"DynHost API Error: HTTP {response.status_code} - {response_text}"

            if response_text.lower().startswith("notfqdn") or response_text.lower().startswith("nohost"):
                return False, "DynHost API Error: Hostname not found or not a FQDN."
            elif response_text.lower().startswith("badrequest"): # Go 코드에는 없지만 DynDNS 표준
                return False, "DynHost API Error: Bad request."
            elif response_text.lower().startswith("good") or response_text.lower().startswith("nochg"):
                # 성공. 요청 IP로 업데이트되었다고 가정.
                return True, f"DynHost update successful for {hostname_for_query}. API Response: '{response_text}'"
            else:
                return False, f"DynHost API Error: Unknown response: '{response_text}'"
        except requests.exceptions.RequestException as e:
            return False, f"DynHost API Request Error: {e}"

    def _build_fqdn_for_dynhost(self):
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"


    # --- API Mode Methods ---
    def _get_adjusted_unix_timestamp(self):
        """OVH 서버 시간과 동기화된 유닉스 타임스탬프 반환 (Go의 getAdjustedUnixTimestamp 참조)"""
        if self.server_time_delta is None:
            self.logger.debug("OVH API: Fetching server time to calculate delta...")
            # /auth/time API 호출 (인증 불필요)
            time_url = urlunparse((self.api_base_url_obj.scheme, self.api_base_url_obj.netloc, 
                                   self.api_base_url_obj.path + "/auth/time", '', '', ''))
            try:
                headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}', 'Accept': 'application/json'}
                response = requests.get(time_url, headers=headers, timeout=self.config.get('http_timeout_seconds', 5))
                response.raise_for_status()
                ovh_server_unix_time = response.json() # 응답이 숫자(타임스탬프)여야 함
                if not isinstance(ovh_server_unix_time, (int, float)):
                    raise ValueError(f"Invalid time format from OVH: {ovh_server_unix_time}")
                
                ovh_time = time.gmtime(int(ovh_server_unix_time)) # UTC로 변환
                local_utc_time = time.gmtime() # 현재 로컬 UTC 시간
                
                # time.mktime은 로컬 시간대 기준 타임스탬프 반환. UTC 타임스탬프 직접 비교.
                self.server_time_delta = int(time.time()) - int(ovh_server_unix_time)
                self.logger.info(f"OVH API: Calculated server time delta: {self.server_time_delta} seconds.")
            except Exception as e:
                self.logger.error(f"OVH API: Failed to get server time or calculate delta: {e}. Using local time (may cause signature issues).")
                self.server_time_delta = 0 # 오류 시 델타 0 (로컬 시간 사용)
        
        # 현재 로컬 UTC 타임스탬프 - 델타 = 조정된 OVH 시간 기준 타임스탬프
        return int(time.time()) - self.server_time_delta


    def _build_api_headers(self, http_method, request_full_url_str, request_body_bytes=None):
        """OVH API 인증 헤더 생성 (Go의 setHeaderCommon, setHeaderAuth 참조)"""
        timestamp = self._get_adjusted_unix_timestamp()
        
        headers = {
            'Accept': 'application/json;charset=utf-8',
            'X-Ovh-Application': self.app_key,
            'X-Ovh-Timestamp': str(timestamp),
            'X-Ovh-Consumer': self.consumer_key,
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}'
        }
        if http_method.upper() in ["POST", "PUT"]:
            headers['Content-Type'] = 'application/json;charset=utf-8'

        body_str = request_body_bytes.decode('utf-8') if request_body_bytes else ""
        
        # 시그니처 생성: AppSecret + '+' + ConsumerKey + '+' + HTTPMethod + '+' + FullURL + '+' + RequestBody + '+' + Timestamp
        raw_signature = f"{self.app_secret}+{self.consumer_key}+{http_method.upper()}+{request_full_url_str}+{body_str}+{timestamp}"
        
        hashed_signature = hashlib.sha1(raw_signature.encode('utf-8')).hexdigest()
        headers['X-Ovh-Signature'] = f"$1${hashed_signature}"
        
        return headers

    def _parse_ovh_api_error(self, response_content_str, status_code):
        """OVH API 오류 응답 파싱 (Go의 extractAPIError 참조)"""
        try:
            error_data = json.loads(response_content_str)
            if isinstance(error_data, dict) and 'Message' in error_data: # Go 코드에서는 대문자 M
                return error_data['Message']
        except json.JSONDecodeError:
            pass
        return response_content_str if response_content_str else f"HTTP {status_code}"


    def _make_ovh_api_request(self, method, endpoint_path, query_params_dict=None, json_payload=None):
        """OVH ZoneDNS API 요청 실행"""
        # URL 구성 (api_base_url_obj 사용)
        path_part = self.api_base_url_obj.path + endpoint_path
        query_str = urlencode(query_params_dict) if query_params_dict else ""
        
        # 시그니처 생성을 위해 전체 URL 필요
        # urlunparse는 query를 문자열로 받음
        full_url_obj = urlparse("")._replace(
            scheme=self.api_base_url_obj.scheme,
            netloc=self.api_base_url_obj.netloc,
            path=path_part,
            query=query_str
        )
        full_url_str = urlunparse(full_url_obj)

        request_body_bytes = None
        if json_payload is not None:
            request_body_bytes = json.dumps(json_payload, separators=(',', ':')).encode('utf-8') # separators로 공백 제거

        headers = self._build_api_headers(method, full_url_str, request_body_bytes)
        timeout = self.config.get('http_timeout_seconds', 10)
        
        self.logger.debug(f"OVH API Request: {method} {full_url_str}")
        if json_payload: self.logger.debug(f"Payload: {json_payload}")
        self.logger.debug(f"Headers: {headers}")


        try:
            if method.upper() == "GET":
                response = requests.get(full_url_str, headers=headers, timeout=timeout) # GET은 query_params가 URL에 이미 포함
            elif method.upper() == "POST":
                response = requests.post(full_url_str, data=request_body_bytes, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(full_url_str, data=request_body_bytes, headers=headers, timeout=timeout)
            else:
                return None, f"Unsupported HTTP method for OVH API: {method}"

            response_content_str = response.text
            self.logger.debug(f"OVH API Response Status: {response.status_code}, Body: '{response_content_str}'")

            if 200 <= response.status_code < 300:
                if not response_content_str and response.status_code in [200, 204]:
                    return {}, None 
                return response.json(), None
            else: 
                error_details = self._parse_ovh_api_error(response_content_str, response.status_code)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                # X-Ovh-Queryid 헤더도 로깅하면 좋음
                query_id = response.headers.get("X-Ovh-Queryid")
                if query_id: error_msg += f" (QueryID: {query_id})"
                
                self.logger.error(f"OVH API call to {method} {full_url_str} failed. {error_msg}")
                if response.status_code == 404:
                    return {"error_type": "NotFound"}, error_msg
                if response.status_code in [401, 403]: # Unauthorized or Forbidden
                    return {"error_type": "AuthError"}, error_msg
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            return None, f"API JSON Decode Error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}"


    def _api_list_record_ids(self, record_type, sub_domain):
        """특정 타입과 서브도메인의 레코드 ID 목록 조회 (Go의 getRecords 참조)"""
        self.logger.debug(f"OVH API: Listing record IDs for type '{record_type}', subdomain '{sub_domain}' in zone '{self.domain}'")
        endpoint_path = f"/domain/zone/{self.domain}/record"
        params = {
            "fieldType": record_type,
            "subDomain": sub_domain # @는 빈 문자열로 전달 (Go 코드 참조)
        }
        data, error_msg = self._make_ovh_api_request("GET", endpoint_path, query_params_dict=params)
        if error_msg:
            # 404는 레코드가 없는 경우일 수 있음 (Go 코드는 오류로 처리)
            if isinstance(data, dict) and data.get("error_type") == "NotFound":
                 self.logger.info(f"OVH API: No records found for type '{record_type}', subdomain '{sub_domain}'.")
                 return [], None # 빈 리스트 반환 (오류 아님)
            return None, error_msg
        
        if isinstance(data, list): # 응답이 레코드 ID 배열
            # OVH API는 숫자 ID를 반환
            record_ids_uint64 = [int(rid) for rid in data if isinstance(rid, (int, float)) or (isinstance(rid, str) and rid.isdigit())]
            return record_ids_uint64, None
        else:
            return None, f"Unexpected response format for list records: {data}"

    def _api_create_record(self, record_type, sub_domain, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"OVH API: Creating new {record_type} record for subdomain '{sub_domain}' in zone '{self.domain}' with IP {ip_address}")
        endpoint_path = f"/domain/zone/{self.domain}/record"
        payload = {
            "fieldType": record_type,
            "subDomain": sub_domain, # @는 빈 문자열
            "target": ip_address,
            # "ttl": self.config.get('ttl') # OVH API는 생성 시 TTL 파라미터가 있는지 확인 필요
        }
        user_ttl = self.config.get('ttl')
        if user_ttl is not None:
            try: payload['ttl'] = int(user_ttl)
            except ValueError: self.logger.warning(f"Invalid TTL '{user_ttl}' in config for create, API default will be used.")

        data, error_msg = self._make_ovh_api_request("POST", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        # 성공 시 응답에 생성된 레코드 정보 포함 (ID 등)
        if isinstance(data, dict) and 'id' in data:
            self.logger.info(f"OVH API: Record created successfully. ID: {data.get('id')}, Target: {data.get('target')}")
            return True, f"Record created successfully (ID: {data.get('id')})."
        else: # 성공했으나 확인 불가
            return True, "Record creation reported success (200/201 OK)."


    def _api_update_record(self, record_id, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        self.logger.info(f"OVH API: Updating RecordId {record_id} in zone '{self.domain}' to IP {ip_address}")
        endpoint_path = f"/domain/zone/{self.domain}/record/{record_id}"
        payload = {
            "target": ip_address,
            # "ttl": self.config.get('ttl') # 업데이트 시 TTL 변경 가능한지 확인
        }
        user_ttl = self.config.get('ttl')
        if user_ttl is not None:
            try: payload['ttl'] = int(user_ttl)
            except ValueError: self.logger.warning(f"Invalid TTL '{user_ttl}' in config for update, existing/default will be used.")

        data, error_msg = self._make_ovh_api_request("PUT", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        
        # 성공 시 응답은 비어있거나 간단한 메시지일 수 있음
        return True, f"Record (ID: {record_id}) update reported success (200 OK)."

    def _api_refresh_zone(self):
        """DNS Zone 새로고침 (Go의 refresh 참조)."""
        self.logger.info(f"OVH API: Refreshing zone '{self.domain}'")
        endpoint_path = f"/domain/zone/{self.domain}/refresh"
        
        data, error_msg = self._make_ovh_api_request("POST", endpoint_path)
        if error_msg:
            return False, error_msg
        return True, "Zone refresh initiated successfully."


    def _update_with_zone_dns(self, ip_address, record_type):
        owner_val = self.config.get('owner', '@')
        sub_domain_for_api = owner_val if owner_val != '@' else "" # API는 @ 대신 빈 문자열

        self.logger.info(f"OVH API: Attempting to update subdomain '{sub_domain_for_api}' for domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        # 1. 기존 레코드 ID 목록 조회
        record_ids, error_msg = self._api_list_record_ids(record_type, sub_domain_for_api)
        if error_msg:
            return False, f"Failed to list existing record IDs: {error_msg}"

        if not record_ids: # 레코드 없음
            self.logger.info(f"OVH API: No existing {record_type} records found for subdomain '{sub_domain_for_api}'. Creating new one.")
            create_success, create_msg = self._api_create_record(record_type, sub_domain_for_api, ip_address)
            if not create_success:
                return False, create_msg
        else: # 레코드 존재, 모두 업데이트 (Go 코드 방식)
            self.logger.info(f"OVH API: Found {len(record_ids)} existing {record_type} record(s) for subdomain '{sub_domain_for_api}'. Updating all.")
            all_updates_ok = True
            update_messages = []
            for rec_id in record_ids:
                # TODO: 업데이트 전에 각 레코드의 현재 IP를 확인하여, IP가 이미 같으면 건너뛰는 로직 추가 가능
                # (GET /domain/zone/{domain}/record/{id} API 필요)
                # 현재 Go 코드는 IP 비교 없이 모든 ID에 대해 업데이트 시도.
                update_success, update_msg = self._api_update_record(rec_id, ip_address)
                update_messages.append(f"RecordID {rec_id}: {update_msg if update_success else 'Failed - ' + update_msg}")
                if not update_success:
                    all_updates_ok = False
            if not all_updates_ok:
                return False, f"One or more record updates failed: {'; '.join(update_messages)}"
        
        # 2. Zone 새로고침
        refresh_success, refresh_msg = self._api_refresh_zone()
        if not refresh_success:
            # 업데이트는 성공했을 수 있으나 새로고침 실패. 경고와 함께 성공으로 처리 가능.
            self.logger.warning(f"OVH API: Record update/creation likely succeeded, but zone refresh failed: {refresh_msg}")
            return True, f"Record update/creation likely succeeded, but zone refresh failed: {refresh_msg}"
            
        return True, f"Successfully updated/created record(s) for subdomain '{sub_domain_for_api}' and refreshed zone."


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        if self.mode == 'api':
            return self._update_with_zone_dns(ip_address, record_type)
        elif self.mode == 'dynhost':
            return self._update_with_dynhost(ip_address, record_type)
        else: # Should have been caught in __init__
            return False, f"Invalid OVH mode: {self.mode}"
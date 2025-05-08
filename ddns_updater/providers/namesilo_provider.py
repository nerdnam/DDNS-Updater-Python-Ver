# ddns_updater/providers/namesilo_provider.py
import json
import requests
from urllib.parse import urlencode

from .base_provider import BaseProvider

class NamesiloProvider(BaseProvider):
    NAME = "namesilo"
    API_BASE_URL = "https://www.namesilo.com"
    # NameSilo TTL 범위 (API 문서 확인 필요, Go 코드는 3600 ~ 2592001)
    MIN_TTL = 3600 
    MAX_TTL = 2592001 

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('namesilo_api_key')
        
        try:
            user_ttl_str = self.config.get('namesilo_ttl')
            if user_ttl_str is not None:
                self.ttl = int(user_ttl_str)
                if self.ttl < self.MIN_TTL:
                    self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} is below minimum {self.MIN_TTL}, using {self.MIN_TTL}.")
                    self.ttl = self.MIN_TTL
                elif self.ttl > self.MAX_TTL:
                    self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} is above maximum {self.MAX_TTL}, using {self.MAX_TTL}.")
                    self.ttl = self.MAX_TTL
            else:
                self.ttl = None # API 기본값 사용 (또는 NameSilo 기본값 명시)
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('namesilo_ttl')}', API default will be used.")
            self.ttl = None
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.api_key, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (namesilo_api_key, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 NameSilo에서 rrhost 구성에 필요.
        return ["namesilo_api_key", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"namesilo_ttl": None} # 기본값은 API 서버에서 결정 또는 NameSilo 기본값

    @staticmethod
    def get_description():
        return "Updates DNS records on NameSilo using their API."

    def _build_common_query_params(self):
        """공통 쿼리 파라미터 생성"""
        return {
            'version': '1',
            'type': 'json',
            'key': self.api_key,
            'domain': self.domain
        }

    def _validate_api_reply_code(self, reply_data):
        """NameSilo API 응답의 reply.code 검증 (Go의 validateResponseCode 참조)"""
        if not isinstance(reply_data, dict):
            return f"Invalid reply format: {reply_data}"

        code_str = reply_data.get('code')
        detail = reply_data.get('detail', 'No details provided.')
        
        if code_str is None:
            return f"Missing 'code' in API reply. Detail: {detail}"
        
        try:
            # NameSilo API는 code를 문자열 또는 숫자로 반환할 수 있음 (Go 코드의 json.Number)
            code = int(str(code_str)) 
        except ValueError:
            return f"Invalid 'code' format in API reply: '{code_str}'. Detail: {detail}"

        # https://www.namesilo.com/api_reference.php#dnsListRecords (Response Codes)
        # 성공 코드는 300
        if code == 300:
            return None # 성공
        
        # 오류 코드 매핑 (주요 코드만 예시)
        error_map = {
            280: "DNS modification error (e.g., invalid record data, record already exists for add)",
            200: "Domain is not active or does not belong to this user",
            110: "Invalid API key",
            112: "API not available to Sub-Accounts",
            113: "API account cannot be accessed from your IP (IP whitelist)",
            201: "Internal system error",
            210: "General error (details in response)",
            # 추가적인 오류 코드들...
        }
        
        error_message = error_map.get(code, "Unknown API error code.")
        return f"API Error (Code: {code}, Detail: {detail}): {error_message}"


    def _make_api_request(self, api_path, query_params_dict):
        """NameSilo API 요청 실행 (항상 GET)"""
        url = f"{self.API_BASE_URL}{api_path}"
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        # 모든 파라미터는 URL 쿼리로 전달
        full_query_params = self._build_common_query_params()
        full_query_params.update(query_params_dict)
        
        try:
            response = requests.get(url, params=full_query_params, headers=headers, timeout=timeout)
            response_content_str = response.text 
            self.logger.debug(f"{self.NAME.capitalize()} API Request to {response.url}, Status: {response.status_code}, Body: '{response_content_str}'")
            
            if response.status_code != 200: # NameSilo는 보통 200 OK 반환 후 내부 코드로 성공/실패 알림
                return None, f"API HTTP Error: {response.status_code} - {response_content_str}"

            try:
                data = response.json()
            except json.JSONDecodeError:
                return None, f"API JSON Decode Error: Failed to parse response: '{response_content_str}'"

            reply = data.get('reply')
            if not reply or not isinstance(reply, dict):
                return None, f"API Error: Invalid or missing 'reply' object in response: {data}"

            validation_error = self._validate_api_reply_code(reply)
            if validation_error:
                return None, validation_error # API 내부 오류 코드에 따른 실패
            
            return reply, None # 성공 시 'reply' 객체 반환
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"NameSilo API request failed: {e}")
            return None, f"API Request Error: {e}"


    def _get_record_info(self, owner_val, record_type_filter):
        """특정 레코드의 ID와 현재 IP 조회 (Go의 getRecord 참조)."""
        self.logger.debug(f"NameSilo: Getting record info for owner '{owner_val}' on domain '{self.domain}' (type: {record_type_filter})")
        
        # dnsListRecords API는 필터링 파라미터가 없음. 모든 레코드 조회 후 필터링.
        reply_data, error_msg = self._make_api_request("/api/dnsListRecords", {})
        if error_msg:
            return None, None, False, error_msg # record_id, current_ip, record_exists, error_message
        
        # 'resource_record'는 레코드가 없을 때 없을 수도 있음 (omitempty)
        records_list = reply_data.get('resource_record', [])
        if not isinstance(records_list, list): # 단일 레코드일 경우 리스트로 변환
            records_list = [records_list] if records_list else []

        # NameSilo는 host에 FQDN을 사용
        fqdn_to_match = self.domain
        if owner_val != '@' and owner_val != '':
            fqdn_to_match = f"{owner_val}.{self.domain}"

        for record_entry in records_list:
            if isinstance(record_entry, dict):
                if (record_entry.get('type') == record_type_filter and
                    record_entry.get('host') == fqdn_to_match): # NameSilo는 'host' 필드에 FQDN
                    
                    record_id_str = record_entry.get('record_id')
                    current_ip = record_entry.get('value')
                    if record_id_str:
                        self.logger.info(f"NameSilo: Found RecordId: {record_id_str} for host '{fqdn_to_match}' with IP: {current_ip}")
                        return record_id_str, current_ip, True, None
        
        self.logger.info(f"NameSilo: No existing record found for host '{fqdn_to_match}' (type: {record_type_filter}) on domain '{self.domain}'.")
        return None, None, False, None # 레코드 없음


    def _build_record_payload_params(self, owner_val, ip_address):
        """레코드 생성/수정 시 공통 쿼리 파라미터 (Go의 buildRecordParams 참조)"""
        params = {
            'rrhost': owner_val if owner_val != '@' else "", # @는 빈 문자열로
            'rrvalue': ip_address,
        }
        if self.ttl is not None:
            params['rrttl'] = str(self.ttl)
        return params

    def _create_dns_record(self, owner_val, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"NameSilo: Creating new {record_type} record for owner '{owner_val}' on domain '{self.domain}' with IP {ip_address}")
        
        query_params = self._build_record_payload_params(owner_val, ip_address)
        query_params['rrtype'] = record_type
        
        reply_data, error_msg = self._make_api_request("/api/dnsAddRecord", query_params)
        if error_msg:
            return False, error_msg 
        
        # 성공 시 (reply.code == 300), 응답에 생성된 record_id가 포함될 수 있음 (문서 확인)
        # Go 코드는 반환값을 확인하지 않음. 여기서는 성공으로 간주.
        new_record_id = reply_data.get('record_id', 'N/A') if isinstance(reply_data, dict) else 'N/A'
        return True, f"Record created successfully (New Record ID: {new_record_id}). Detail: {reply_data.get('detail', '')}"


    def _update_existing_record(self, record_id_str, owner_val, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        self.logger.info(f"NameSilo: Updating RecordId {record_id_str} (owner '{owner_val}') on domain '{self.domain}' to IP {ip_address}")
        
        query_params = self._build_record_payload_params(owner_val, ip_address)
        query_params['rrid'] = record_id_str
        
        reply_data, error_msg = self._make_api_request("/api/dnsUpdateRecord", query_params)
        if error_msg:
            return False, error_msg
        
        return True, f"Record updated successfully (ID: {record_id_str}). Detail: {reply_data.get('detail', '')}"


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"NameSilo: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        # 1. 기존 레코드 정보 (ID 및 현재 IP) 조회
        record_id, current_ip, record_exists, error_msg = self._get_record_info(owner_val, record_type)
        
        if error_msg: 
            return False, f"Failed to get existing record info: {error_msg}"
        
        if not record_exists:
            self.logger.info(f"NameSilo: Record for owner '{owner_val}' (type: {record_type}) not found. Creating new one.")
            create_success, create_msg = self._create_dns_record(owner_val, record_type, ip_address)
            return create_success, create_msg
        
        # 레코드 존재
        if current_ip == ip_address:
            msg = f"NameSilo: IP address {ip_address} for owner '{owner_val}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        self.logger.info(f"NameSilo: Record ID {record_id} for owner '{owner_val}' ({record_type}) found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
        update_success, update_msg = self._update_existing_record(record_id, owner_val, ip_address)
        return update_success, update_msg
# ddns_updater/providers/porkbun_provider.py
import json
import requests
# import strconv # <--- 삭제됨

from .base_provider import BaseProvider

class PorkbunProvider(BaseProvider):
    NAME = "porkbun"
    API_BASE_URL = "https://api.porkbun.com/api/json/v3/dns"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.api_key = self.config.get('porkbun_api_key')
        self.secret_api_key = self.config.get('porkbun_secret_api_key')
        
        try:
            # Porkbun TTL은 문자열로 전달, 기본값 300 (API 문서 확인 필요)
            # 설정 파일에서 읽은 값을 정수로 변환 시도 후 다시 문자열로 저장
            ttl_value_from_config = self.config.get('porkbun_ttl', '300') # 기본값을 문자열 '300'으로
            parsed_ttl_int = int(ttl_value_from_config) # 정수 변환 시도 (유효성 검사 목적)
            
            # Porkbun 최소/최대 TTL 확인 필요 (예시: 60 ~ 86400)
            # if parsed_ttl_int < 60:
            #     self.logger.warning(f"Porkbun TTL {parsed_ttl_int} is below minimum, adjusting to 60.")
            #     parsed_ttl_int = 60
            # elif parsed_ttl_int > 86400: # 예시 최대값
            #     self.logger.warning(f"Porkbun TTL {parsed_ttl_int} is above maximum, adjusting to 86400.")
            #     parsed_ttl_int = 86400
            self.ttl_str = str(parsed_ttl_int) # 최종적으로 문자열로 저장
        except ValueError:
            self.logger.warning(f"Invalid TTL value '{self.config.get('porkbun_ttl')}' for Porkbun, using default '300'.")
            self.ttl_str = "300" 
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        if not all([self.api_key, self.secret_api_key, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (porkbun_api_key, porkbun_secret_api_key, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        return ["porkbun_api_key", "porkbun_secret_api_key", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"porkbun_ttl": "300"} # 기본값을 문자열로 명시

    @staticmethod
    def get_description():
        return "Updates DNS records on Porkbun using their API (v3)."

    def _build_auth_payload(self):
        return {
            "apikey": self.api_key,
            "secretapikey": self.secret_api_key
        }

    def _parse_porkbun_error(self, response_content_str, status_code):
        try:
            error_data = json.loads(response_content_str)
            if isinstance(error_data, dict):
                status = error_data.get('status', '').upper()
                message = error_data.get('message', 'No specific error message from API.')
                if status == "ERROR":
                    return message
                else: 
                    return f"Status: {status}, Message: {message}"
        except json.JSONDecodeError:
            pass 
        return response_content_str if response_content_str else f"HTTP {status_code}"

    def _make_api_request(self, endpoint_path_suffix, payload_dict, decode_response_body=True):
        url = f"{self.API_BASE_URL}{endpoint_path_suffix}"
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        timeout = self.config.get('http_timeout_seconds', 10)
        
        full_payload = self._build_auth_payload()
        if payload_dict: # payload_dict가 None이 아닐 때만 update
            full_payload.update(payload_dict)

        self.logger.debug(f"Porkbun API Request to {url}, Payload: {json.dumps(full_payload)}") # 로깅 시 JSON 문자열로

        try:
            response = requests.post(url, json=full_payload, headers=headers, timeout=timeout)
            response_content_str = response.text 
            self.logger.debug(f"Porkbun API Response Status: {response.status_code}, Body: '{response_content_str}'")

            if response.status_code == 200:
                if not decode_response_body: 
                    return {"status": "SUCCESS"}, None 
                
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    if not response_content_str: return {"status": "SUCCESS"}, None
                    return None, f"API JSON Decode Error: Failed to parse success response: '{response_content_str}'"

                if isinstance(data, dict) and data.get('status', '').upper() == 'SUCCESS':
                    return data, None 
                else: 
                    error_details = self._parse_porkbun_error(response_content_str, response.status_code)
                    return None, f"API Error (Unexpected status in 200 OK): {error_details}"
            else: 
                error_details = self._parse_porkbun_error(response_content_str, response.status_code)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                if "invalid apikey or secretapikey" in error_details.lower():
                    return {"error_type": "AuthError"}, error_msg
                return None, error_msg
            
        except requests.exceptions.RequestException as e:
            return None, f"API Request Error: {e}"

    def _list_records(self, record_type, owner_val):
        self.logger.debug(f"Porkbun: Listing records for type '{record_type}', owner '{owner_val}' on domain '{self.domain}'")
        
        endpoint_suffix = f"/retrieveByNameType/{self.domain}/{record_type}/"
        # Porkbun API는 owner가 @일 때 경로에서 owner 부분을 생략하거나,
        # 또는 owner가 @가 아닐 때만 경로에 추가. Go 코드는 @가 아니면 추가.
        if owner_val != '@' and owner_val != '':
            endpoint_suffix += owner_val 
        
        data, error_msg = self._make_api_request(endpoint_suffix, {}) # 요청 본문에는 인증 정보만
        if error_msg:
            self.logger.warning(f"Porkbun: Error listing records or no records found. Assuming no records. Error: {error_msg}")
            return [], None # 오류 발생 시 또는 레코드 없을 시 빈 리스트 (호출부에서 None 체크)

        if data and 'records' in data and isinstance(data['records'], list):
            return data['records'], None 
        else: 
            self.logger.info(f"Porkbun: No 'records' field in response or unexpected format. Assuming no records. Response: {data}")
            return [], None 

    def _create_dns_record(self, owner_val, record_type, ip_address):
        self.logger.info(f"Porkbun: Creating new {record_type} record for owner '{owner_val}' on domain '{self.domain}' with IP {ip_address}")
        endpoint_suffix = f"/create/{self.domain}"
        
        payload = {
            "content": ip_address,
            "type": record_type,
            "ttl": self.ttl_str, 
        }
        if owner_val != '@' and owner_val != '':
            payload["name"] = owner_val # Porkbun은 owner가 @일 때 name 필드 생략 가능
        
        data, error_msg = self._make_api_request(endpoint_suffix, payload, decode_response_body=False)
        if error_msg:
            return False, error_msg
        
        return True, f"Record created successfully for owner '{owner_val}'."


    def _update_existing_record(self, record_id_str, owner_val, record_type, ip_address):
        self.logger.info(f"Porkbun: Updating RecordID {record_id_str} (owner '{owner_val}', type {record_type}) on domain '{self.domain}' to IP {ip_address}")
        
        endpoint_suffix = f"/edit/{self.domain}/{record_id_str}"
        payload = {
            "content": ip_address,
            "type": record_type, 
            "ttl": self.ttl_str,
        }
        if owner_val != '@' and owner_val != '':
            payload["name"] = owner_val

        data, error_msg = self._make_api_request(endpoint_suffix, payload, decode_response_body=False)
        if error_msg:
            return False, error_msg
        
        return True, f"Record (ID: {record_id_str}) updated successfully."

    def _delete_record_by_name_type(self, record_type, owner_val):
        self.logger.info(f"Porkbun: Deleting all {record_type} records for owner '{owner_val}' on domain '{self.domain}'")
        endpoint_suffix = f"/deleteByNameType/{self.domain}/{record_type}/"
        if owner_val != '@' and owner_val != '':
            endpoint_suffix += owner_val
        
        data, error_msg = self._make_api_request(endpoint_suffix, {}, decode_response_body=False)
        if error_msg:
            return False, error_msg
        return True, f"Deletion request sent for {record_type} records of owner '{owner_val}'."

    def _delete_conflicting_records_if_needed(self, owner_val, record_type_to_create):
        self.logger.debug(f"Porkbun: Checking for default conflicting records for owner '{owner_val}'.")
        
        porkbun_parked_domain = "pixie.porkbun.com" 
        records_to_check_and_delete = []

        if owner_val == '@':
            records_to_check_and_delete.append({"type": "ALIAS", "owner": "@", "content": porkbun_parked_domain})
        elif owner_val == '*':
            records_to_check_and_delete.append({"type": "CNAME", "owner": "*", "content": porkbun_parked_domain})
        
        if not records_to_check_and_delete:
            return True, "No default conflicting records to check for this owner."

        all_deleted_successfully = True
        messages = []

        for rec_info in records_to_check_and_delete:
            existing_records, err_list = self._list_records(rec_info["type"], rec_info["owner"])
            if err_list: # _list_records에서 오류 발생 시
                messages.append(f"Error listing potential conflicting {rec_info['type']} record for {rec_info['owner']}: {err_list}")
                all_deleted_successfully = False
                continue
            
            found_and_matches = False
            if existing_records: 
                for ex_rec in existing_records:
                    if isinstance(ex_rec, dict) and ex_rec.get('content', '').lower() == rec_info["content"].lower():
                        found_and_matches = True
                        break 
            
            if found_and_matches:
                self.logger.info(f"Porkbun: Found default conflicting record: {rec_info['type']} {rec_info['owner']} -> {rec_info['content']}. Attempting to delete.")
                delete_success, delete_msg = self._delete_record_by_name_type(rec_info["type"], rec_info["owner"])
                messages.append(f"Deletion of {rec_info['type']} {rec_info['owner']}: {delete_msg if delete_success else 'Failed - ' + delete_msg}")
                if not delete_success:
                    all_deleted_successfully = False
            else:
                messages.append(f"No conflicting default {rec_info['type']} record found for {rec_info['owner']} with content {rec_info['content']}.")
        
        return all_deleted_successfully, "; ".join(messages) if messages else "No conflicting records processed."


    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"Porkbun: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        existing_records, error_msg = self._list_records(record_type, owner_val)
        if error_msg: 
            return False, f"Failed to list existing records: {error_msg}"
        
        if not existing_records: 
            self.logger.info(f"Porkbun: No existing {record_type} records found for owner '{owner_val}'. Checking for conflicting defaults and creating new one.")
            delete_conflict_success, delete_conflict_msg = self._delete_conflicting_records_if_needed(owner_val, record_type)
            if not delete_conflict_success:
                self.logger.warning(f"Porkbun: Failed to delete potential conflicting records, creation might fail or have unintended side effects. Details: {delete_conflict_msg}")
            
            create_success, create_msg = self._create_dns_record(owner_val, record_type, ip_address)
            return create_success, create_msg
        
        all_updates_successful = True
        update_messages = []
        ip_already_set_for_at_least_one_record = False

        for record_data in existing_records:
            if not isinstance(record_data, dict): continue

            record_id_str = record_data.get('id')
            current_ip = record_data.get('content')

            if not record_id_str:
                self.logger.warning(f"Porkbun: Found record for owner '{owner_val}' but it has no ID. Skipping. Data: {record_data}")
                update_messages.append(f"Skipped record with no ID for owner '{owner_val}'.")
                all_updates_successful = False # ID 없는 레코드는 문제
                continue

            if current_ip == ip_address:
                msg = f"Porkbun: IP address {ip_address} for record ID {record_id_str} (owner '{owner_val}') is already up to date."
                self.logger.info(msg)
                update_messages.append(msg)
                ip_already_set_for_at_least_one_record = True
                continue 
            
            self.logger.info(f"Porkbun: Record ID {record_id_str} (owner '{owner_val}') found with different IP. Current: {current_ip}, New: {ip_address}. Updating.")
            update_success, update_msg = self._update_existing_record(record_id_str, owner_val, record_type, ip_address)
            update_messages.append(f"Update for RecordID {record_id_str}: {update_msg if update_success else 'Failed - ' + update_msg}")
            if not update_success:
                all_updates_successful = False
        
        if not all_updates_successful:
             return False, f"One or more record updates failed: {'; '.join(update_messages)}"
        
        if ip_already_set_for_at_least_one_record and all_updates_successful:
             # 모든 레코드가 이미 최신이거나, 다른 IP를 가진 레코드들이 성공적으로 업데이트된 경우
             return True, f"IP for {owner_val} was already up to date for some records and/or other records updated successfully. Details: {'; '.join(update_messages)}"

        # 모든 레코드가 업데이트 대상이었고, 모두 성공한 경우
        return True, f"All relevant records for owner '{owner_val}' updated successfully. Details: {'; '.join(update_messages)}"
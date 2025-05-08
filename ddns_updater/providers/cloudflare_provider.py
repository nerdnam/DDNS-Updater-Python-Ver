# ddns_updater/providers/cloudflare_provider.py
import json
import sys # stderr 출력을 위해 (이제 self.logger.debug로 대체)
import requests 
import logging # 로거 사용을 위해 임포트

from .base_provider import BaseProvider 

class CloudflareProvider(BaseProvider):
    NAME = "cloudflare"
    API_BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self, config: dict, logger: logging.Logger):
        super().__init__(config, logger) 
        
        # --- 디버깅 로그를 self.logger.debug()로 변경 ---
        self.logger.debug(f"CloudflareProvider __init__ received config type: {type(config)} for section '{config.get('section_name')}'")
        try:
            config_str_for_log = json.dumps(config, indent=2)
        except TypeError: 
            config_str_for_log = str(config)
        self.logger.debug(f"CloudflareProvider __init__ received config content:\n{config_str_for_log}")
        
        token_key_str = 'cloudflare_token'
        api_key_key_str = 'cloudflare_api_key'
        email_key_str = 'cloudflare_email'
        zone_id_key_str = 'cloudflare_zone_id'
        proxied_key_str = 'proxied'
        ttl_key_str = 'ttl'

        self.api_token = config.get(token_key_str) 
        self.api_key = config.get(api_key_key_str)     
        self.email = config.get(email_key_str)         
        self.zone_id = config.get(zone_id_key_str)
        
        self.logger.debug(f"CloudflareProvider __init__ Raw from config - api_token: '{self.api_token}' (type: {type(self.api_token)})")
        self.logger.debug(f"CloudflareProvider __init__ Raw from config - api_key: '{self.api_key}' (type: {type(self.api_key)})")
        self.logger.debug(f"CloudflareProvider __init__ Raw from config - email: '{self.email}' (type: {type(self.email)})")
        self.logger.debug(f"CloudflareProvider __init__ Raw from config - zone_id: '{self.zone_id}' (type: {type(self.zone_id)})")
        # ---------------------------------------------
        
        proxied_config = config.get(proxied_key_str, False) 
        if isinstance(proxied_config, str):
            self.proxied = proxied_config.lower() == 'true'
        else:
            self.proxied = bool(proxied_config)
            
        try:
            self.ttl = int(config.get(ttl_key_str, 1)) 
            if self.ttl < 1 and self.ttl != 1: 
                self.logger.warning(
                    f"{self.NAME.capitalize()} provider: TTL value {self.ttl} is invalid. "
                    f"Must be 1 (for Auto) or a positive integer (e.g., >=60). Defaulting to 1 (Auto)."
                )
                self.ttl = 1
        except ValueError:
            self.logger.warning(
                f"{self.NAME.capitalize()} provider: Invalid TTL value '{config.get(ttl_key_str)}' "
                f"in configuration. Defaulting to 1 (Auto)."
            )
            self.ttl = 1

        auth_method_used = None
        if self.api_token and isinstance(self.api_token, str) and self.api_token.strip(): 
            auth_method_used = "API Token"
            self.logger.debug("CloudflareProvider __init__ Auth Check: Using API Token.") 
            if self.api_key or self.email: 
                self.logger.info(
                    f"{self.NAME.capitalize()} provider: API Token found and will be used. "
                    f"Global API Key and Email settings will be ignored."
                )
            self.api_key = None 
            self.email = None   
        elif self.api_key and isinstance(self.api_key, str) and self.api_key.strip() and \
             self.email and isinstance(self.email, str) and self.email.strip(): 
            auth_method_used = "Global API Key + Email"
            self.logger.debug("CloudflareProvider __init__ Auth Check: Using Global API Key + Email.") 
            self.logger.warning(
                f"{self.NAME.capitalize()} provider: Using Global API Key and Email for authentication. "
                f"It is recommended to use an API Token for better security and granular permissions."
            )
        else: 
            error_msg = (
                f"{self.NAME.capitalize()} provider: Authentication required. "
                f"Either 'cloudflare_api_token' OR both 'cloudflare_api_key' AND 'cloudflare_email' must be provided."
            )
            self.logger.error(error_msg)
            self.logger.debug(f"CloudflareProvider __init__ FAILED AUTH CHECK. Values - " 
                              f"api_token: '{self.api_token}' (type: {type(self.api_token)}), "
                              f"api_key: '{self.api_key}' (type: {type(self.api_key)}), "
                              f"email: '{self.email}' (type: {type(self.email)})")
            raise ValueError(error_msg) 
        
        self.logger.debug(f"{self.NAME.capitalize()} provider: Using authentication method: {auth_method_used}")
            
        if not self.zone_id or not isinstance(self.zone_id, str) or not self.zone_id.strip(): 
            error_msg = f"{self.NAME.capitalize()} provider: 'cloudflare_zone_id' is required and must be a non-empty string. Found: '{self.zone_id}' (type: {type(self.zone_id)})"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        return ["cloudflare_zone_id"] 

    @staticmethod
    def get_optional_config_fields():
        return {
            "cloudflare_api_token": None,
            "cloudflare_api_key": None,
            "cloudflare_email": None,
            "proxied": False, 
            "ttl": 1          
        }

    @staticmethod
    def get_description():
        return "Updates DNS records on Cloudflare using their API v4. Supports API Token (recommended) or Global API Key + Email."

    def _build_headers(self):
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}', 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if self.api_token: 
            headers['Authorization'] = f'Bearer {self.api_token}'
        elif self.api_key and self.email:
            headers['X-Auth-Email'] = self.email
            headers['X-Auth-Key'] = self.api_key
        return headers

    def _make_api_request(self, method: str, endpoint_path: str, params: dict = None, data: dict = None) -> tuple[dict | None, str | None]:
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = self._build_headers()
        timeout = self.config.get('http_timeout_seconds', 10) 

        self.logger.debug(f"Cloudflare API Request: {method} {url}")
        if params: self.logger.debug(f"Query Params: {params}")
        if data: self.logger.debug(f"JSON Payload: {json.dumps(data, indent=2)}")
        
        try:
            response = requests.request(method, url, params=params, json=data, headers=headers, timeout=timeout)
            
            response_content_for_log = "No content"
            try:
                response_content_for_log = json.dumps(response.json(), indent=2)
            except json.JSONDecodeError:
                response_content_for_log = response.text
            self.logger.debug(f"Cloudflare API Response Status: {response.status_code}, Body:\n{response_content_for_log}")

            response.raise_for_status() 
            
            if not response.content and response.status_code in [200, 201, 204]:
                 self.logger.debug(f"Cloudflare API: Received empty response for {method} {endpoint_path}, assuming success based on status code {response.status_code}.")
                 return {"success": True, "result": {}}, None 

            response_json = response.json()

            if response_json.get("success") is True:
                return response_json, None 
            else:
                errors_list = response_json.get("errors", [])
                error_messages = "; ".join([f"Error {err.get('code')}: {err.get('message')}" for err in errors_list])
                full_error_msg = f"API call successful but operation failed. Errors: {error_messages if error_messages else 'No specific error messages.'}"
                self.logger.error(full_error_msg)
                return None, full_error_msg

        except requests.exceptions.HTTPError as e:
            error_body = e.response.text
            self.logger.error(f"Cloudflare API HTTP error: {e.response.status_code} - {error_body}", exc_info=True)
            try: 
                error_data = json.loads(error_body)
                errors_list = error_data.get("errors", [])
                error_messages = "; ".join([f"Error {err.get('code')}: {err.get('message')}" for err in errors_list])
                return None, f"API HTTP Error: {e.response.status_code} - {error_messages if error_messages else error_body}"
            except json.JSONDecodeError:
                return None, f"API HTTP Error: {e.response.status_code} - {error_body}"
        except requests.exceptions.RequestException as e: 
            self.logger.error(f"Cloudflare API request failed: {e}", exc_info=True)
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e: 
            self.logger.error(f"Cloudflare API JSON decode error after successful HTTP status: {e}. Response: {response.text if 'response' in locals() else 'N/A'}", exc_info=True)
            return None, f"API JSON Decode Error after successful HTTP status: {e}"


    def _find_record_id(self, record_name: str, record_type: str) -> tuple[str | None, str | None, str | None]:
        self.logger.debug(f"Cloudflare: Finding record ID for name '{record_name}' (type: {record_type}) in zone '{self.zone_id}'")
        
        endpoint_path = f"/zones/{self.zone_id}/dns_records"
        params = {
            'type': record_type,
            'name': record_name, 
            'page': 1,
            'per_page': 1 
        }

        response_data, error_msg = self._make_api_request("GET", endpoint_path, params=params)
        
        if error_msg:
            return None, None, error_msg 
        
        if response_data and response_data.get("success") is True:
            results = response_data.get("result", [])
            if len(results) == 1:
                record = results[0]
                record_id = record.get("id")
                current_ip = record.get("content")
                # 추가: 현재 레코드의 proxied 상태와 ttl도 가져와서 비교에 사용 가능
                # current_proxied = record.get("proxied")
                # current_ttl = record.get("ttl")
                self.logger.info(f"Cloudflare: Found RecordId: {record_id} for name '{record_name}' with IP: {current_ip}")
                return record_id, current_ip, None # 필요시 current_proxied, current_ttl도 반환
            elif len(results) == 0:
                self.logger.info(f"Cloudflare: No existing record found for name '{record_name}' (type: {record_type}).")
                return None, None, None 
            else: 
                msg = f"Cloudflare: Multiple records found for name '{record_name}' (type: {record_type}). This should not happen with per_page=1."
                self.logger.warning(msg)
                return None, None, msg
        else: 
            return None, None, "Failed to get record info due to API error (success: false or unexpected format)."


    def _create_dns_record(self, record_name: str, record_type: str, ip_address: str) -> tuple[str | None, str | None]:
        self.logger.info(f"Cloudflare: Creating new {record_type} record for name '{record_name}' with IP {ip_address}")
        
        endpoint_path = f"/zones/{self.zone_id}/dns_records"
        payload = {
            'type': record_type,
            'name': record_name, 
            'content': ip_address,
            'proxied': self.proxied, # __init__에서 설정된 값 사용
            'ttl': self.ttl         # __init__에서 설정된 값 사용
        }

        response_data, error_msg = self._make_api_request("POST", endpoint_path, data=payload)
        
        if error_msg:
            return None, error_msg 
        
        if response_data and response_data.get("success") is True and \
           isinstance(response_data.get("result"), dict) and response_data["result"].get("id"):
            record_id = response_data["result"]["id"]
            self.logger.info(f"Cloudflare: Successfully created record. New RecordId: {record_id}")
            return record_id, None
        else:
            return None, "Failed to create record or no RecordId in response after successful API call."


    def _update_dns_record(self, record_id: str, record_name: str, record_type: str, ip_address: str) -> tuple[bool, str | None]:
        self.logger.info(f"Cloudflare: Updating RecordId {record_id} (name '{record_name}', type {record_type}) to IP {ip_address}")
        
        endpoint_path = f"/zones/{self.zone_id}/dns_records/{record_id}"
        payload = {
            'type': record_type, 
            'name': record_name, 
            'content': ip_address,
            'proxied': self.proxied, # __init__에서 설정된 값 사용
            'ttl': self.ttl         # __init__에서 설정된 값 사용
        }

        response_data, error_msg = self._make_api_request("PUT", endpoint_path, data=payload)
        
        if error_msg:
            return False, error_msg 
        
        if response_data and response_data.get("success") is True:
            updated_content = response_data.get("result", {}).get("content")
            if updated_content == ip_address:
                self.logger.info(f"Cloudflare: Successfully updated RecordId {record_id}. New IP confirmed: {updated_content}")
                return True, f"Record updated successfully to IP {ip_address}."
            else:
                msg = (f"Cloudflare: Successfully updated RecordId {record_id}, but API returned content "
                       f"'{updated_content}' instead of '{ip_address}'. This might be a propagation delay or an issue.")
                self.logger.warning(msg)
                return True, msg 
        else:
            return False, "Failed to update record or unexpected success response format."


    def update_record(self, ip_address: str, record_type: str = "A", proxied: bool = None) -> tuple[bool, str]:
        # 인자로 받은 proxied 값 처리 (선택적: 인자 우선 또는 설정 우선)
        # 현재는 __init__에서 설정된 self.proxied를 사용.
        # 만약 인자로 받은 proxied를 우선하려면 아래 주석 해제 및 로직 수정.
        # effective_proxied = self.proxied
        # if proxied is not None and proxied != self.proxied:
        #     self.logger.info(
        #         f"Cloudflare: 'proxied' argument ({proxied}) from update_record call differs from "
        #         f"config value ({self.proxied}). Using argument value: {proxied}."
        #     )
        #     effective_proxied = proxied 
        #     # self.proxied = proxied # 만약 인스턴스 변수 자체를 변경하고 싶다면
        # # 이후 _create_dns_record, _update_dns_record 호출 시 effective_proxied 전달 또는 self.proxied 사용

        record_name_to_update = self._get_fqdn() 
        
        self.logger.info(
            f"Cloudflare: Attempting to update name '{record_name_to_update}' ({record_type}) "
            f"in zone '{self.zone_id}' to IP: {ip_address} (Proxied: {self.proxied}, TTL: {self.ttl})"
        )

        # 1. 기존 레코드 ID 및 현재 IP (그리고 필요시 다른 속성) 조회
        # _find_record_id가 (record_id, current_ip, error_message)를 반환한다고 가정
        record_id, current_ip, error_msg_find = self._find_record_id(record_name_to_update, record_type)
        
        if error_msg_find: 
            return False, f"Failed to find existing record: {error_msg_find}"
        
        if record_id: # 레코드 존재
            # TODO: IP 외에 TTL, Proxied 상태도 변경되었는지 확인하고 업데이트할지 결정하는 로직 추가 가능
            # 현재는 IP만 비교.
            # 예를 들어, _find_record_id가 (id, ip, proxied_state, ttl_val, error)를 반환하게 하고,
            # if current_ip == ip_address and self.proxied == proxied_state and self.ttl == ttl_val:
            # 와 같이 비교할 수 있음.
            if current_ip == ip_address:
                msg = f"IP address {ip_address} for name '{record_name_to_update}' is already up to date. (Proxied/TTL status not checked for changes)."
                self.logger.info(msg)
                return True, msg 
            
            # IP가 다르면 업데이트
            self.logger.info(f"IP address for '{record_name_to_update}' needs update. Current: {current_ip}, New: {ip_address}")
            update_success, update_msg = self._update_dns_record(
                record_id, record_name_to_update, record_type, ip_address
            )
            return update_success, update_msg or "Failed to update record." 
        else: # 레코드 없음
            self.logger.info(f"No existing {record_type} record found for '{record_name_to_update}'. Creating new one.")
            new_record_id, create_error_msg = self._create_dns_record(
                record_name_to_update, record_type, ip_address
            )
            if create_error_msg:
                return False, f"Failed to create new record: {create_error_msg}"
            if new_record_id:
                return True, f"Successfully created new record (ID: {new_record_id}) for name '{record_name_to_update}' with IP {ip_address}."
            else: 
                return False, f"Failed to create record for name '{record_name_to_update}', no RecordId returned but no explicit error."
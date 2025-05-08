# ddns_updater/providers/digitalocean_provider.py
import json
import requests

from .base_provider import BaseProvider

class DigitaloceanProvider(BaseProvider):
    NAME = "digitalocean"
    API_BASE_URL = "https://api.digitalocean.com/v2"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('digitalocean_token')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (digitalocean_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 DigitalOcean에서 레코드 이름(name 필드)에 사용됨.
        return ["digitalocean_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # DigitalOcean API는 레코드 생성/수정 시 TTL, priority, port, weight 등도 지원.
        # 필요시 이들을 optional_fields로 추가하고 update_record에서 사용 가능.
        # 여기서는 Go 코드의 단순성을 따라 TTL 등은 일단 제외.
        return {"ttl": None} # 예시, 실제 지원 여부 및 기본값 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on DigitalOcean using their API (v2)."

    def _build_headers(self):
        return {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/json', # PUT/POST 요청 시 필요
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.token}'
        }

    def _build_record_search_name(self):
        """GET /records 쿼리 파라미터 'name'에 사용될 FQDN 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    def _make_api_request(self, method, endpoint_path, params=None, data=None):
        """DigitalOcean API 요청 실행"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = self._build_headers()
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if method.upper() == "GET":
                response = requests.get(url, params=params, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=headers, timeout=timeout)
            # 필요시 POST 등 다른 메소드 추가
            # elif method.upper() == "POST":
            #     response = requests.post(url, json=data, headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None, f"Unsupported HTTP method: {method}"

            response.raise_for_status()
            
            if not response.content and response.status_code in [200, 201, 204]:
                 self.logger.debug(f"DigitalOcean API: Received empty response for {method} {endpoint_path}, assuming success based on status code {response.status_code}.")
                 return {"message": "Operation successful, no content returned."}, None

            return response.json(), None
        except requests.exceptions.HTTPError as e:
            error_body = e.response.text
            self.logger.error(f"DigitalOcean API HTTP error: {e.response.status_code} - {error_body}")
            try:
                error_data = json.loads(error_body)
                # DigitalOcean 오류 응답은 보통 'id'와 'message'를 포함
                error_id = error_data.get("id", "UnknownErrorID")
                error_message = error_data.get("message", "No message in error response")
                return None, f"API HTTP Error: {e.response.status_code} (ID: {error_id}, Message: {error_message})"
            except json.JSONDecodeError:
                return None, f"API HTTP Error: {e.response.status_code} - {error_body}"
        except requests.exceptions.RequestException as e:
            self.logger.error(f"DigitalOcean API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            response_text = response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'
            self.logger.error(f"DigitalOcean API JSON decode error: {e}. Response: {response_text}")
            return None, f"API JSON Decode Error: {e}"

    def _get_record_info(self, record_type_filter):
        """지정된 타입의 DNS 레코드 ID와 현재 IP 값을 조회 (Go의 getRecordID 참조)."""
        # DigitalOcean API는 name (FQDN)과 type으로 레코드를 필터링.
        record_search_name = self._build_record_search_name() # 예: sub.example.com 또는 example.com
        
        self.logger.debug(f"DigitalOcean: Finding record info for name '{record_search_name}' (type: {record_type_filter}) in domain '{self.domain}'")
        
        endpoint_path = f"/domains/{self.domain}/records"
        params = {
            'name': record_search_name,
            'type': record_type_filter
        }

        data, error_msg = self._make_api_request("GET", endpoint_path, params=params)
        if error_msg:
            return None, None, False, error_msg # record_id, current_ip, record_exists, error_message
        
        if data and 'domain_records' in data:
            records = data['domain_records']
            if len(records) == 1:
                record = records[0]
                record_id = record.get('id')
                current_ip = record.get('data') # DigitalOcean은 'data' 필드에 IP 저장
                if record_id and isinstance(record_id, int) and record_id > 0:
                    self.logger.info(f"DigitalOcean: Found RecordId: {record_id} for name '{record_search_name}' with IP: {current_ip}")
                    return record_id, current_ip, True, None
                else: # ID가 없거나 유효하지 않은 경우
                    msg = f"DigitalOcean: Found a record for '{record_search_name}', but RecordId is invalid: {record_id}."
                    self.logger.error(msg)
                    return None, None, False, msg
            elif len(records) == 0:
                self.logger.info(f"DigitalOcean: No existing record found for name '{record_search_name}' (type: {record_type_filter}).")
                return None, None, False, None # 레코드 없음
            else: # len(records) > 1
                msg = f"DigitalOcean: Multiple records found for name '{record_search_name}' (type: {record_type_filter}). Please ensure unique records or refine search."
                self.logger.warning(msg)
                # 여러 개 중 첫 번째 것을 사용할 수도 있지만, Go 코드는 오류로 처리. 여기서는 일단 오류로.
                return None, None, False, msg
        else:
            msg = f"DigitalOcean: Failed to get record info or unexpected response format. Response: {data}"
            self.logger.error(msg)
            return None, None, False, msg

    def _update_dns_record(self, record_id, record_type, owner_for_payload, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 Update 함수 일부)."""
        self.logger.info(f"DigitalOcean: Updating RecordId {record_id} (owner '{owner_for_payload}', type {record_type}) in domain '{self.domain}' to IP {ip_address}")
        
        endpoint_path = f"/domains/{self.domain}/records/{record_id}"
        payload = {
            'type': record_type,
            'name': owner_for_payload, # DigitalOcean API는 'name' 필드에 owner(@, www 등)를 기대
            'data': ip_address
            # TTL 등 다른 필드도 필요시 추가 가능
        }

        data, error_msg = self._make_api_request("PUT", endpoint_path, data=payload)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        if data and 'domain_record' in data:
            updated_ip = data['domain_record'].get('data')
            if updated_ip == ip_address:
                self.logger.info(f"DigitalOcean: Successfully updated RecordId {record_id}. New IP confirmed: {updated_ip}")
                return True, f"Successfully updated RecordId {record_id} to IP {ip_address}."
            else:
                msg = f"DigitalOcean: Successfully updated RecordId {record_id}, but API returned IP '{updated_ip}' instead of '{ip_address}'."
                self.logger.warning(msg)
                return True, msg # 일단 성공으로 처리하나 경고
        else:
            msg = f"DigitalOcean: Failed to update record or unexpected response format. Response: {data}"
            self.logger.error(msg)
            return False, msg

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@') # PUT 요청의 'name' 필드에 사용될 값

        self.logger.info(f"DigitalOcean: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        record_id, current_ip, record_exists, error_msg = self._get_record_info(record_type)
        
        if error_msg:
            return False, error_msg
        
        if not record_exists:
            # Go 코드는 레코드 없으면 오류. DigitalOcean API는 레코드 생성 기능도 있지만,
            # 이 DDNS 클라이언트의 Go 버전은 업데이트만 가정.
            # 필요하다면 여기에 _create_dns_record 로직 추가.
            # (API: POST /v2/domains/{domain_name}/records)
            msg = f"DigitalOcean: Record for owner '{owner_val}', type '{record_type}' on domain '{self.domain}' does not exist. Auto-creation not implemented in this version (matching Go client behavior)."
            self.logger.error(msg)
            return False, msg

        if current_ip == ip_address:
            msg = f"DigitalOcean: IP address {ip_address} for owner '{owner_val}' on domain '{self.domain}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 업데이트
        success, msg = self._update_dns_record(record_id, record_type, owner_val, ip_address)
        return success, msg
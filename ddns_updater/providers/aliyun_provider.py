# ddns_updater/providers/aliyun_provider.py
import hashlib
import hmac
import base64
import time
import uuid
import json
from urllib.parse import quote # RFC3986 기준 퍼센트 인코딩 (safe='~' 기본값)

import requests # HTTP 요청 라이브러리

from .base_provider import BaseProvider

class AliyunProvider(BaseProvider):
    NAME = "aliyun"
    API_VERSION = "2015-01-09"  # Go 코드와 동일, 최신 버전 확인 권장
    # API 엔드포인트 (공식 문서에서 정확한 범용 엔드포인트 확인 필요)
    # Go 코드에서는 DescribeDomainRecords는 dns.aliyuncs.com, 나머지는 alidns.aliyuncs.com 사용
    # 여기서는 일단 alidns.aliyuncs.com 으로 통일하고, 필요시 액션별로 다르게 처리
    API_ENDPOINT_HOST = "alidns.aliyuncs.com"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.access_key_id = self.config.get('aliyun_access_key_id')
        self.access_key_secret = self.config.get('aliyun_access_key_secret')
        # self.domain 은 BaseProvider 에서 이미 설정됨 (config.get('domain'))
        self.region_id = self.config.get('aliyun_region_id') # 사용자가 명시적으로 설정 가능

        # 필수 설정값 확인
        if not all([self.access_key_id, self.access_key_secret, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (aliyun_access_key_id, aliyun_access_key_secret, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        self.api_base_url = f"https://{self.API_ENDPOINT_HOST}/"


    @staticmethod
    def get_required_config_fields():
        return ["aliyun_access_key_id", "aliyun_access_key_secret", "domain"]

    @staticmethod
    def get_optional_config_fields():
        # owner는 BaseProvider에서 기본값 '@'를 가질 수 있음
        # region_id는 사용자가 설정하지 않으면 API 요청 시 포함하지 않거나, 기본값(예: cn-hangzhou) 사용 가능
        return {"aliyun_region_id": None, "ttl": 600, "owner": "@"}

    @staticmethod
    def get_description():
        return "Updates DNS records on Aliyun (Alibaba Cloud DNS)."

    def _percent_encode(self, string_to_encode):
        """
        RFC3986에 따른 퍼센트 인코딩.
        Go의 url.QueryEscape는 공백을 %20으로, '+'는 그대로 '+'로 둡니다.
        urllib.parse.quote(s, safe='~')는 공백을 %20으로, '+'를 %2B로 인코딩합니다.
        Aliyun API 문서에서 정확한 인코딩 규칙 확인이 중요합니다.
        여기서는 Go의 url.QueryEscape와 유사하게 '+'는 인코딩하지 않도록 safe에 추가.
        (주의: Aliyun API가 '+'를 어떻게 처리하는지 확인 필요. 일반적으로는 '+'도 인코딩 대상)
        """
        return quote(str(string_to_encode), safe='~+-*') # Go의 url.QueryEscape와 유사하게 시도

    def _build_common_parameters(self, action):
        """Aliyun API 공통 요청 파라미터 생성 (Go의 newURLValues 참조)"""
        params = {
            'Format': 'JSON',
            'Version': self.API_VERSION,
            'AccessKeyId': self.access_key_id,
            'SignatureMethod': 'HMAC-SHA1',
            'Timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            'SignatureVersion': '1.0',
            'SignatureNonce': str(uuid.uuid4()), # Go의 랜덤 정수 대신 UUID 사용
            'Action': action,
        }
        if self.region_id: # region_id가 설정된 경우에만 파라미터에 추가
            params['RegionId'] = self.region_id
        return params

    def _sign_request(self, parameters, http_method="GET"):
        """Aliyun API 요청 서명 생성 (Go의 sign 함수 참조)"""
        # 1. 파라미터 정렬 (키 기준 오름차순) 및 인코딩된 쿼리 문자열 조각 생성
        #    Go 코드는 "key=value" 형태로 만들고 각 조각을 정렬 후 join.
        #    여기서는 key와 value를 각각 인코딩하고, 정렬된 순서대로 조합.
        sorted_encoded_params = []
        for k, v in sorted(parameters.items()):
            # 각 키와 값을 퍼센트 인코딩
            encoded_k = self._percent_encode(k)
            encoded_v = self._percent_encode(v)
            sorted_encoded_params.append(f"{encoded_k}={encoded_v}")
        
        # 2. 정규화된 쿼리 문자열 생성
        canonicalized_query_string = "&".join(sorted_encoded_params)

        # 3. 서명 문자열 생성
        #    Go 코드: strings.ToUpper(method) + "&%2F&" + url.QueryEscape(strings.Join(sortedParams, "&"))
        #    여기서 url.QueryEscape(strings.Join(sortedParams, "&"))는 canonicalized_query_string을 다시 인코딩하는 것.
        #    Aliyun 문서 확인 필요: canonicalized_query_string 자체를 인코딩하는지, 아니면 인코딩된 조각들을 join한 것을 그대로 사용하는지.
        #    일반적으로는 이미 인코딩된 조각들을 join한 것을 그대로 사용.
        string_to_sign = (
            http_method.upper() + "&" +
            self._percent_encode("/") + "&" +
            self._percent_encode(canonicalized_query_string) # Go 코드와 동일하게 canonicalized_query_string을 한번 더 인코딩
        )

        # 4. 서명 계산 (HMAC-SHA1)
        signature_key = (self.access_key_secret + "&").encode('utf-8')
        hashed = hmac.new(signature_key, string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(hashed.digest()).decode('utf-8')
        
        return signature

    def _make_api_request(self, params, http_method="GET"):
        """Aliyun API 요청 실행"""
        # 서명 추가
        params['Signature'] = self._sign_request(params.copy(), http_method)

        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}', # 간단한 User-Agent
            'Accept': 'application/json'
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            if http_method.upper() == "GET":
                response = requests.get(self.api_base_url, params=params, headers=headers, timeout=timeout)
            # Aliyun DNS API는 대부분 GET 요청을 사용하는 것으로 보임 (Go 코드 기준)
            # 필요시 POST 등 다른 메소드 추가
            # elif http_method.upper() == "POST":
            #     response = requests.post(self.api_base_url, data=params, headers=headers, timeout=timeout)
            else:
                self.logger.error(f"Unsupported HTTP method: {http_method}")
                return None, f"Unsupported HTTP method: {http_method}"

            response.raise_for_status() # HTTP 오류 발생 시 예외 발생
            
            # 일부 성공 응답이 빈 내용일 수 있으므로 확인
            if not response.content:
                self.logger.debug(f"Aliyun API: Received empty response for action {params.get('Action')}, assuming success based on status code {response.status_code}.")
                return {}, None # 빈 딕셔너리 반환 (성공으로 간주)

            return response.json(), None
        except requests.exceptions.HTTPError as e:
            error_body = e.response.text
            self.logger.error(f"Aliyun API HTTP error: {e.response.status_code} - {error_body}")
            # API 오류 응답에서 Code와 Message를 파싱하려는 시도
            try:
                error_data = json.loads(error_body)
                api_code = error_data.get("Code", "UnknownCode")
                api_message = error_data.get("Message", "No message in error response")
                return None, f"API HTTP Error: {e.response.status_code} (Code: {api_code}, Message: {api_message})"
            except json.JSONDecodeError:
                return None, f"API HTTP Error: {e.response.status_code} - {error_body}"
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Aliyun API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e:
            # response.text가 정의되어 있는지 확인
            response_text = response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'
            self.logger.error(f"Aliyun API JSON decode error: {e}. Response: {response_text}")
            return None, f"API JSON Decode Error: {e}"

    def _get_record_info(self, record_name_owner, record_type):
        """지정된 도메인 이름과 타입의 레코드 ID 및 현재 IP 값을 조회 (Go의 getRecordID 참조)."""
        self.logger.debug(f"Aliyun: Finding record info for owner '{record_name_owner}' on domain '{self.domain}' (type: {record_type})")
        
        params = self._build_common_parameters('DescribeDomainRecords')
        params['DomainName'] = self.domain
        params['RRKeyWord'] = record_name_owner
        params['Type'] = record_type # Go 코드에서는 TypeKeyWord가 아닌 Type 사용, 문서 확인 필요

        data, error_msg = self._make_api_request(params, http_method="GET")
        if error_msg:
            return None, None, error_msg # record_id, current_ip, error_message
        
        if data and data.get('DomainRecords') and data['DomainRecords'].get('Record'):
            records = data['DomainRecords']['Record']
            if len(records) == 1:
                record_id = records[0].get('RecordId')
                current_ip = records[0].get('Value')
                self.logger.info(f"Aliyun: Found RecordId: {record_id} for RR '{record_name_owner}' with IP: {current_ip}")
                return record_id, current_ip, None
            elif len(records) > 1:
                msg = f"Aliyun: Multiple records found for RR '{record_name_owner}' (type: {record_type}). Please ensure unique records."
                self.logger.warning(msg)
                return None, None, msg
            else: # len(records) == 0
                self.logger.info(f"Aliyun: No existing record found for RR '{record_name_owner}' (type: {record_type}).")
                return None, None, None # 레코드 없음 (오류는 아님)
        else: # 응답 형식이 다르거나 DomainRecords.Record가 없는 경우
            self.logger.info(f"Aliyun: No existing record found (or unexpected response format) for RR '{record_name_owner}' (type: {record_type}). Response: {data}")
            return None, None, None 

    def _create_record(self, record_name_owner, record_type, ip_address):
        """새로운 DNS 레코드를 생성 (Go의 createRecord 참조)."""
        self.logger.info(f"Aliyun: Creating new {record_type} record for RR '{record_name_owner}' on domain '{self.domain}' with IP {ip_address}")
        
        params = self._build_common_parameters('AddDomainRecord')
        params['DomainName'] = self.domain
        params['RR'] = record_name_owner
        params['Type'] = record_type
        params['Value'] = ip_address
        params['TTL'] = self.config.get('ttl', 600)

        data, error_msg = self._make_api_request(params, http_method="GET") # Go 코드 기준 GET
        if error_msg:
            return None, error_msg # record_id, error_message
        
        if data and data.get('RecordId'):
            record_id = data['RecordId']
            self.logger.info(f"Aliyun: Successfully created record. New RecordId: {record_id}")
            return record_id, None
        else:
            msg = f"Aliyun: Failed to create record or no RecordId in response. Response: {data}"
            self.logger.error(msg)
            return None, msg

    def _update_existing_record(self, record_id, record_name_owner, record_type, ip_address):
        """기존 DNS 레코드를 업데이트 (Go의 updateRecord 참조)."""
        self.logger.info(f"Aliyun: Updating RecordId {record_id} (RR '{record_name_owner}', type {record_type}) to IP {ip_address}")
        
        params = self._build_common_parameters('UpdateDomainRecord')
        params['RecordId'] = record_id
        params['RR'] = record_name_owner
        params['Type'] = record_type
        params['Value'] = ip_address
        params['TTL'] = self.config.get('ttl', 600)

        # UpdateDomainRecord는 성공 시 응답 바디가 비어있거나 간단할 수 있음
        data, error_msg = self._make_api_request(params, http_method="GET") # Go 코드 기준 GET
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        # _make_api_request에서 HTTP 오류는 이미 처리됨. 여기까지 오면 성공으로 간주.
        # (data가 비어있을 수 있으므로 data 내용에 의존하지 않음)
        self.logger.info(f"Aliyun: Successfully updated RecordId {record_id}.")
        return True, f"Successfully updated RecordId {record_id}."

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"Aliyun provider does not use the 'proxied' option. It will be ignored.")

        record_name_owner = self.config.get('owner', '@')
        
        self.logger.info(f"Aliyun: Attempting to update RR '{record_name_owner}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        record_id, current_ip, error_msg = self._get_record_info(record_name_owner, record_type)
        
        if error_msg: # _get_record_info 에서 오류 발생
            return False, error_msg
        
        if record_id: # 레코드 존재
            if current_ip == ip_address:
                msg = f"Aliyun: IP address {ip_address} for RR '{record_name_owner}' is already up to date."
                self.logger.info(msg)
                return True, msg # 이미 최신 상태도 성공으로 처리
            
            # IP가 다르면 업데이트
            success, msg = self._update_existing_record(record_id, record_name_owner, record_type, ip_address)
            return success, msg
        else: # 레코드 없음 (current_ip도 None일 것임)
            # 새로 생성
            new_record_id, create_error_msg = self._create_record(record_name_owner, record_type, ip_address)
            if create_error_msg:
                return False, create_error_msg
            if new_record_id:
                return True, f"Successfully created new record for RR '{record_name_owner}' with IP {ip_address}."
            else: # 이론적으로는 create_error_msg 에서 걸러져야 함
                return False, f"Failed to create record for RR '{record_name_owner}', no RecordId returned."
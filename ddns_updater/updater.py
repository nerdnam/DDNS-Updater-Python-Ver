# /ddns-updater-python-ver-ipv4/ddns_updater/updater.py
import logging
import sys 
from .ip_fetcher import get_public_ipv4
from .providers import get_provider_class # providers/__init__.py 에서 가져옴

def update_single_record(logger: logging.Logger, 
                         record_config_dict: dict, 
                         global_config_dict: dict) -> tuple[bool, str | None, str]:
    """
    주어진 설정에 따라 단일 DDNS 레코드 업데이트를 수행합니다 (현재 IPv4만 지원).
    
    반환값: (update_overall_success, new_or_current_ip, message_string)
    - update_overall_success (bool): 
        IP가 성공적으로 업데이트되었거나, 이미 최신 상태여서 변경이 필요 없었으면 True.
        IP 조회 실패, 프로바이더 API 호출 실패 등 실제 작업에 문제가 있었으면 False.
        이 값은 state.py의 new_info_dict['update_successful']로 사용될 수 있습니다.
    - new_or_current_ip (str | None): 
        성공적으로 설정된 IP 주소 (새 IP 또는 기존 IP). 실패 시 None.
        이 값은 state.py의 new_info_dict['current_ip']로 사용될 수 있습니다.
    - message_string (str): 
        업데이트 결과에 대한 상세 메시지.
        이 값은 state.py의 new_info_dict['status_message']로 사용될 수 있습니다.
    """
    provider_name = record_config_dict.get('provider', '').lower()
    domain = record_config_dict.get('domain')
    owner = record_config_dict.get('owner', '@') 
    section_name = record_config_dict.get('section_name')

    if not section_name:
        logger.error("Configuration missing 'section_name'. Cannot proceed with update.")
        return False, None, "Internal error: section_name missing in record_config."
    if not provider_name:
        logger.error(f"[{section_name}] Provider not specified in configuration.")
        return False, None, "Provider not specified."
    if not domain:
        logger.error(f"[{section_name}] Domain not specified in configuration.")
        return False, None, "Domain not specified."

    full_domain_log = f"{owner}.{domain}" if owner != "@" else domain
    logger.info(f"Processing update for record [{section_name}]: {full_domain_log} via {provider_name}")

    ip_version_setting = record_config_dict.get('ip_version', 'ipv4').lower()
    if ip_version_setting != 'ipv4':
        msg = f"Unsupported ip_version '{ip_version_setting}' for record [{section_name}]. Only 'ipv4' is currently supported."
        logger.warning(msg)
        return False, None, msg # 작업 실패
    
    record_type_to_update = "A"

    # --- 1. 현재 공인 IP 주소 가져오기 ---
    http_timeout_seconds = record_config_dict.get('http_timeout_seconds', 
                                               global_config_dict.get('default_http_timeout_seconds', 10))
    logger.info(f"[{section_name}] Fetching public IPv4 address with timeout {http_timeout_seconds}s...")
    current_public_ip = get_public_ipv4(logger=logger, timeout_seconds=http_timeout_seconds)

    if not current_public_ip:
        msg = f"Failed to fetch current public IPv4 address for record [{section_name}]."
        logger.error(msg)
        return False, None, msg # 작업 실패

    logger.info(f"[{section_name}] Current public IPv4 address: {current_public_ip}")

    # --- 2. 프로바이더 클라이언트 초기화 및 업데이트 실행 ---
    ProviderClass = get_provider_class(provider_name)
    if not ProviderClass:
        msg = f"Unsupported or uninitialized provider: '{provider_name}' for record [{section_name}]. Check provider implementation and registration."
        logger.error(msg)
        return False, None, msg # 작업 실패

    try:
        provider_instance = ProviderClass(config=record_config_dict, logger=logger)
        
        proxied_setting = record_config_dict.get('proxied', False)

        logger.info(f"[{section_name}] Calling provider '{provider_name}' to update record to IP {current_public_ip} (type: {record_type_to_update}, proxied: {proxied_setting})")
        
        # 프로바이더의 update_record는 (api_call_success_bool, message_str)을 반환한다고 가정
        api_call_success, provider_message = provider_instance.update_record(
            ip_address=current_public_ip,
            record_type=record_type_to_update,
            proxied=proxied_setting
        )

        if api_call_success:
            # 프로바이더 API 호출이 성공했음을 의미 (IP가 실제로 변경되었든, 이미 최신이었든)
            logger.info(f"[{section_name}] Provider API call successful. Message: {provider_message}")
            # 성공 시, new_or_current_ip는 우리가 조회한 current_public_ip
            return True, current_public_ip, provider_message 
        else:
            # 프로바이더 API 호출 자체가 실패했음을 의미
            logger.error(f"[{section_name}] Provider API call failed. Message: {provider_message}")
            return False, None, provider_message # 작업 실패

    except ValueError as ve: # 프로바이더 초기화 시 설정 오류 등
        logger.error(f"[{section_name}] Configuration error for provider {provider_name}: {ve}", exc_info=True)
        return False, None, f"Provider configuration error: {ve}" # 작업 실패
    except Exception as e: # 프로바이더 update_record 내부의 예외 등
        logger.exception(f"[{section_name}] Unexpected error during update with provider {provider_name}: {e}")
        return False, None, f"Provider internal error: {str(e)}" # 작업 실패
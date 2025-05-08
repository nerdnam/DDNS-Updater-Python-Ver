# /ddns-updater-python-ver-ipv4/ddns_updater/ip_fetcher.py
import requests
import logging
import sys

DEFAULT_REQUEST_TIMEOUT = 10 
DEFAULT_USER_AGENT = 'Python-DDNS-Updater/1.0'

IPV4_SERVICES = [
    "https://api.ipify.org",
    "https://v4.ident.me",
    "https://ipv4.icanhazip.com",
    "https://api.seeip.org/ip",
    "https://ipinfo.io/ip",
    "https://checkip.amazonaws.com",
]

module_logger = logging.getLogger("ddns_updater.ip_fetcher")
# 핸들러 설정은 main_logger나 app.logger를 통해 전파되거나,
# run.py에서 명시적으로 설정될 수 있음. 여기서는 중복 핸들러 방지 로직 제거.

def _get_ip_from_service(url, logger_to_use, timeout_seconds, user_agent):
    try:
        service_name = url.split('/')[2] if '//' in url else url
    except IndexError:
        service_name = url
    
    logger_to_use.debug(f"Attempting to get IP from {service_name} ({url}) with timeout {timeout_seconds}s...")
    try:
        headers = {'User-Agent': user_agent}
        response = requests.get(url, timeout=timeout_seconds, headers=headers)
        response.raise_for_status()
        ip_address = response.text.strip()

        if ip_address and '.' in ip_address and len(ip_address.split('.')) == 4:
            all_octets_valid = True
            for octet in ip_address.split('.'):
                if not octet.isdigit() or not (0 <= int(octet) <= 255):
                    all_octets_valid = False
                    break
            if all_octets_valid:
                logger_to_use.info(f"Successfully retrieved IPv4 from {service_name}: {ip_address}")
                return ip_address
            else:
                logger_to_use.warning(f"Invalid IPv4 format received from {service_name}: '{ip_address}'")
                return None
        else:
            logger_to_use.warning(f"Non-IPv4 or invalid format received from {service_name}: '{ip_address}'")
            return None
            
    except requests.exceptions.HTTPError as e:
        logger_to_use.warning(f"HTTP error from {service_name}: {e.response.status_code} {e.response.reason}")
        return None
    except requests.exceptions.RequestException as e: 
        logger_to_use.warning(f"Network error (RequestException) while connecting to {service_name}: {e}")
        return None
    except Exception as e: 
        logger_to_use.warning(f"An unexpected error occurred while processing {service_name}: {e}", exc_info=True)
        return None

def get_public_ipv4(logger: logging.Logger = None, timeout_seconds: int = DEFAULT_REQUEST_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT) -> str | None:
    actual_logger = logger if logger else module_logger

    for service_url in IPV4_SERVICES:
        ip = _get_ip_from_service(service_url, actual_logger, timeout_seconds, user_agent)
        if ip: 
            return ip
            
    actual_logger.error("Failed to retrieve public IPv4 from all configured services.")
    return None
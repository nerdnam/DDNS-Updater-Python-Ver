# /ddns-updater-python-ver-ipv4/ddns_updater/config.py
import configparser
import sys
import os
from .utils import parse_duration

CONFIG_FILE_NAME = 'ddns_config.ini' 

def _get_config_file_path(project_root_dir=None):
    # ... (이전과 동일) ...
    if project_root_dir is None:
        try:
            current_file_dir = os.path.dirname(os.path.abspath(__file__))
            project_root_dir = os.path.dirname(current_file_dir)
        except NameError: 
            project_root_dir = os.getcwd() 
    return os.path.join(project_root_dir, CONFIG_FILE_NAME)


def clean_value(value):
    # ... (이전과 동일) ...
    if value is None:
        return None
    return str(value).split(';', 1)[0].strip()

def read_global_config(config_file_path=None, project_root_dir=None):
    if config_file_path is None:
        config_file_path = _get_config_file_path(project_root_dir)
    
    config = configparser.ConfigParser(inline_comment_prefixes=';', interpolation=None)
    
    defaults = {
        'nick': 'default_nick',
        'default_timezone': 'Etc/UTC',
        'default_http_timeout': '10s',
        'default_http_timeout_seconds': 10,
        'debug_mode': False # ★★★ 디버그 모드 기본값 False ★★★
    }
    global_settings = defaults.copy()

    if not os.path.exists(config_file_path):
        print(f"Warning (config.read_global_config): Global config file {config_file_path} not found. Using default global settings.", file=sys.stderr)
        return global_settings
        
    try:
        config.read(config_file_path, encoding='utf-8')
        if 'ddns' in config:
            section = config['ddns']
            global_settings['nick'] = clean_value(section.get('nick', defaults['nick']))
            global_settings['default_timezone'] = clean_value(section.get('default_timezone', defaults['default_timezone']))
            
            timeout_str = clean_value(section.get('default_http_timeout', defaults['default_http_timeout']))
            global_settings['default_http_timeout'] = timeout_str
            
            parsed_timeout_seconds = parse_duration(timeout_str)
            if parsed_timeout_seconds is not None:
                global_settings['default_http_timeout_seconds'] = parsed_timeout_seconds
            
            # --- ★★★ 디버그 모드 설정 읽기 ★★★ ---
            debug_mode_str = clean_value(section.get('debug_mode', 'false')) # 기본값 'false' 문자열
            global_settings['debug_mode'] = debug_mode_str.lower() == 'true' # 불리언으로 변환
            # ------------------------------------
            
    except configparser.Error as e:
        print(f"Error (config.read_global_config): reading global config from {config_file_path}: {e}. Using default global settings.", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error (config.read_global_config): reading global config from {config_file_path}: {e}. Using default global settings.", file=sys.stderr)
    
    return global_settings

# --- read_config 및 write_global_config 함수는 이전과 동일하게 유지 ---
def read_config(config_file_path=None, project_root_dir=None):
    # ... (이전 코드와 동일) ...
    if config_file_path is None:
        config_file_path = _get_config_file_path(project_root_dir)
        
    config_parser_obj = configparser.ConfigParser(inline_comment_prefixes=';', interpolation=None) 
    records = []
    
    global_defaults = read_global_config(config_file_path=config_file_path, project_root_dir=project_root_dir)

    if not os.path.exists(config_file_path):
        print(f"Warning (config.read_config): Config file not found at {config_file_path}. No records loaded.", file=sys.stderr)
        return records 
        
    try:
        parsed_files = config_parser_obj.read(config_file_path, encoding='utf-8')
        if not parsed_files: 
            print(f"Warning (config.read_config): Could not read config file {config_file_path}. No records loaded.", file=sys.stderr)
            return records

    except configparser.Error as e:
        print(f"Error (config.read_config): parsing config file {config_file_path}: {e}. No records loaded.", file=sys.stderr)
        return records

    for section_name in config_parser_obj.sections(): 
        if section_name.lower() == 'ddns': 
            continue

        section = config_parser_obj[section_name] 
        if not section.get('domain') or not section.get('provider'):
            print(f"Warning (config.read_config): Skipping section [{section_name}] due to missing 'domain' or 'provider'.", file=sys.stderr)
            continue
            
        settings = {'section_name': section_name}
        try:
            settings['domain'] = clean_value(section.get('domain')) 
            settings['provider'] = clean_value(section.get('provider'))
            settings['owner'] = clean_value(section.get('owner', '@')) 
            settings['ip_version'] = clean_value(section.get('ip_version', 'ipv4')).lower()
            
            proxied_str = clean_value(section.get('proxied', 'false'))
            settings['proxied'] = proxied_str.lower() == 'true'

            update_period_str = clean_value(section.get('update_period', '1h')) 
            settings['update_period'] = update_period_str
            settings['update_period_seconds'] = parse_duration(update_period_str) or 3600 

            cooldown_period_str = clean_value(section.get('cooldown_period', '6h')) 
            settings['cooldown_period'] = cooldown_period_str
            settings['cooldown_period_seconds'] = parse_duration(cooldown_period_str) or (6 * 3600)

            http_timeout_str = clean_value(section.get('http_timeout', global_defaults['default_http_timeout']))
            settings['http_timeout'] = http_timeout_str
            settings['http_timeout_seconds'] = parse_duration(http_timeout_str) or global_defaults['default_http_timeout_seconds']

            settings['timezone'] = clean_value(section.get('timezone', global_defaults['default_timezone']))
            
            known_keys = ['domain', 'provider', 'owner', 'ip_version', 'proxied', 
                          'update_period', 'cooldown_period', 'http_timeout', 'timezone']
            for key, value in section.items():
                if key not in known_keys:
                    settings[key] = clean_value(value)
            
            records.append(settings)
        except Exception as e:
            print(f"Warning (config.read_config): Skipping section [{section_name}] due to error reading settings: {e}", file=sys.stderr)
            
    return records

def write_global_config(settings_dict, config_file_path=None, project_root_dir=None):
    if config_file_path is None:
        config_file_path = _get_config_file_path(project_root_dir)
        
    config = configparser.ConfigParser(inline_comment_prefixes=';', interpolation=None)
    
    if os.path.exists(config_file_path):
        try:
            config.read(config_file_path, encoding='utf-8')
        except configparser.Error as e:
            print(f"Warning (config.write_global_config): Could not read existing config {config_file_path} for writing: {e}", file=sys.stderr)

    if 'ddns' not in config:
        config.add_section('ddns')

    # debug_mode도 저장 가능하도록 keys_to_save에 추가 (선택 사항)
    keys_to_save = ['nick', 'default_timezone', 'default_http_timeout', 'debug_mode']
    for key in keys_to_save:
        if key in settings_dict: # None 값도 저장 (예: debug_mode = None)
            if settings_dict[key] is not None:
                 config['ddns'][key] = str(settings_dict[key])
            elif key in config['ddns']: # 명시적으로 None으로 제거 요청 시
                 del config['ddns'][key]
        # settings_dict에 키가 없으면 기존 값 유지

    try:
        config_dir = os.path.dirname(config_file_path)
        if not os.path.exists(config_dir) and config_dir: 
            os.makedirs(config_dir, exist_ok=True)
            
        with open(config_file_path, 'w', encoding='utf-8') as configfile:
            config.write(configfile)
        return True, "Global settings saved successfully."
    except IOError as e:
        print(f"Error (config.write_global_config): writing global settings to {config_file_path}: {e}", file=sys.stderr)
        return False, f"Error writing config file: {e}"
    except Exception as e:
        print(f"Unexpected error (config.write_global_config): saving global settings: {e}", file=sys.stderr)
        return False, f"Unexpected error saving config: {e}"
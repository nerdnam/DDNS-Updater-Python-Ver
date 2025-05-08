# /ddns-updater-python-ver-ipv4/ddns_updater/state.py
import json
import os
import sys
from datetime import datetime, timezone as dt_timezone, timedelta 
import pytz 

STATE_FILE_NAME = 'ddns_state.json'
MAX_PREVIOUS_IPS = 3 # 이전 IP 저장 개수를 3개로 설정

def _get_state_file_path(project_root_dir=None):
    if project_root_dir is None:
        try:
            current_file_dir = os.path.dirname(os.path.abspath(__file__))
            project_root_dir = os.path.dirname(current_file_dir)
        except NameError:
            project_root_dir = os.getcwd()
    return os.path.join(project_root_dir, STATE_FILE_NAME)

def load_state(state_file_path=None, project_root_dir=None):
    if state_file_path is None:
        state_file_path = _get_state_file_path(project_root_dir)
        
    if not os.path.exists(state_file_path):
        return {} 
        
    try:
        with open(state_file_path, 'r', encoding='utf-8') as f:
            state_data = json.load(f)
            if not isinstance(state_data, dict):
                print(f"Warning (state.load_state): State file {state_file_path} does not contain a valid dictionary. Returning empty state.", file=sys.stderr)
                return {}
            return state_data
    except json.JSONDecodeError as e:
        print(f"Error (state.load_state): decoding JSON from state file {state_file_path}: {e}. Returning empty state.", file=sys.stderr)
        return {}
    except IOError as e:
        print(f"Error (state.load_state): loading state file {state_file_path}: {e}. Returning empty state.", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"Unexpected error (state.load_state): loading state file {state_file_path}: {e}. Returning empty state.", file=sys.stderr)
        return {}

def save_state(state_data_dict, state_file_path=None, project_root_dir=None):
    if state_file_path is None:
        state_file_path = _get_state_file_path(project_root_dir)

    if not isinstance(state_data_dict, dict):
        print(f"Error (state.save_state): Attempting to save non-dictionary data to state file.", file=sys.stderr)
        return False, "Invalid data type for saving state (must be a dictionary)."
        
    try:
        state_dir = os.path.dirname(state_file_path)
        if not os.path.exists(state_dir) and state_dir:
            os.makedirs(state_dir, exist_ok=True)
            
        with open(state_file_path, 'w', encoding='utf-8') as f:
            json.dump(state_data_dict, f, indent=2, ensure_ascii=False)
        return True, "State saved successfully."
    except IOError as e:
        print(f"Error (state.save_state): writing state file {state_file_path}: {e}", file=sys.stderr)
        return False, f"Error writing state file: {e}"
    except Exception as e:
        print(f"An unexpected error (state.save_state): occurred saving state: {e}", file=sys.stderr)
        return False, f"An unexpected error occurred saving state: {e}"

def update_record_state(section_id: str, 
                        new_info_dict: dict, 
                        record_timezone_str: str = 'Etc/UTC', 
                        project_root_dir: str = None) -> tuple[bool, str]:
    if not section_id:
        return False, "Section ID (section_name) cannot be empty for state update."

    current_full_state = load_state(project_root_dir=project_root_dir)
    record_specific_state = current_full_state.setdefault(section_id, {})

    try:
        # --- previous_ips 업데이트 로직 (옵션 2 적용) ---
        previous_ips = record_specific_state.get('previous_ips', [])
        # 상태 업데이트 *전*의 current_ip 값을 old_current_ip로 사용
        old_current_ip = record_specific_state.get('current_ip') 
        
        update_attempted = 'last_attempt_utc' in new_info_dict

        if update_attempted and old_current_ip: 
            # IP 변경 여부와 관계없이 old_current_ip를 previous_ips에 추가 시도.
            # 단, previous_ips의 가장 최근 값(previous_ips[0])과 old_current_ip가 동일하면 중복 추가 방지.
            if not previous_ips or previous_ips[0] != old_current_ip:
                previous_ips.insert(0, old_current_ip) # 가장 최근에 사용된 IP를 맨 앞에 추가
            record_specific_state['previous_ips'] = previous_ips[:MAX_PREVIOUS_IPS]
        elif 'previous_ips' not in record_specific_state: 
            record_specific_state['previous_ips'] = []
        # ---------------------------------------------

        # current_ip 업데이트
        if 'current_ip' in new_info_dict:
            new_ip_from_update = new_info_dict.get('current_ip')
            record_specific_state['current_ip'] = new_ip_from_update if new_ip_from_update is not None else ""
        elif 'current_ip' not in record_specific_state: 
            record_specific_state.setdefault('current_ip', "")


        # 상태 메시지 (status1)
        status_message_from_update = new_info_dict.get('status_message', "Unknown status")
        update_call_successful = new_info_dict.get('update_successful', False) 

        if update_call_successful: 
            record_specific_state['status1'] = "Updated" 
        else: 
            record_specific_state['status1'] = "Update Failed"
        
        # last_success_update_timestamp_utc 처리
        if update_call_successful and 'last_attempt_utc' in new_info_dict:
            last_success_dt_utc = new_info_dict['last_attempt_utc']
            if isinstance(last_success_dt_utc, datetime):
                 if last_success_dt_utc.tzinfo is None:
                     last_success_dt_utc = last_success_dt_utc.replace(tzinfo=dt_timezone.utc)
                 record_specific_state['last_success_update_timestamp_utc'] = last_success_dt_utc.timestamp()
        elif 'last_success_update_timestamp_utc' not in record_specific_state: 
            record_specific_state.setdefault('last_success_update_timestamp_utc', None)


        # 마지막 업데이트 시도 시간 (UTC) - 항상 기록
        last_attempt_utc_dt = new_info_dict.get('last_attempt_utc')
        if isinstance(last_attempt_utc_dt, datetime):
            if last_attempt_utc_dt.tzinfo is None: 
                last_attempt_utc_dt = last_attempt_utc_dt.replace(tzinfo=dt_timezone.utc)
            
            try:
                target_tz = pytz.timezone(record_timezone_str)
            except pytz.UnknownTimeZoneError:
                print(f"Warning (state.update_record_state): Unknown timezone '{record_timezone_str}' for section '{section_id}'. Using UTC.", file=sys.stderr)
                target_tz = pytz.utc
            
            localized_dt = last_attempt_utc_dt.astimezone(target_tz)

            record_specific_state['date1'] = localized_dt.strftime('%Y-%m-%d')
            record_specific_state['date2'] = localized_dt.strftime('%y-%m-%d')
            record_specific_state['time1'] = localized_dt.strftime('%H:%M:%S')
            record_specific_state['time2'] = localized_dt.strftime('%H:%M')
            record_specific_state['status2'] = localized_dt.strftime('%y-%m-%d %H:%M') 
            record_specific_state['status3'] = localized_dt.strftime('%m-%d %H:%M') 
            
            record_specific_state['last_attempt_timestamp_utc'] = last_attempt_utc_dt.timestamp()

        for key in ['status1', 'status2', 'current_ip', 'date1', 'date2', 'time1', 'time2', 'status3']:
            record_specific_state.setdefault(key, "")
        record_specific_state.setdefault('previous_ips', [])
        record_specific_state.setdefault('last_success_update_timestamp_utc', None)
        record_specific_state.setdefault('last_attempt_timestamp_utc', None)

        current_full_state[section_id] = record_specific_state

    except Exception as e:
        print(f"Error (state.update_record_state): processing state update for section {section_id}: {e}", file=sys.stderr)
        print(f"DEBUG (state.update_record_state): new_info_dict was: {new_info_dict}", file=sys.stderr)
        return False, f"Error processing state update: {e}"

    return save_state(current_full_state, project_root_dir=project_root_dir)
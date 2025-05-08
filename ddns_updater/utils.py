# /ddns-updater-python-ver-ipv4/ddns_updater/utils.py
import re
import sys
from datetime import timedelta

def parse_duration(duration_str):
    """
    Duration string (e.g., '1h', '30m', '10s', '1h30m') to seconds (integer).
    Returns None if parsing fails.
    """
    if not isinstance(duration_str, str):
        print(f"Warning (utils.parse_duration): Invalid duration type (expected string): {duration_str}", file=sys.stderr)
        return None

    duration_str = duration_str.lower().strip()
    if not duration_str:
        return None

    total_seconds = 0
    pattern = re.compile(r"(\d+)\s*(h|m|s)")
    parts = pattern.findall(duration_str)
    
    parsed_something = False
    original_duration_str_for_error_msg = duration_str 

    for value_str, unit in parts:
        try:
            val = int(value_str)
            if unit == 'h':
                total_seconds += val * 3600
            elif unit == 'm':
                total_seconds += val * 60
            elif unit == 's':
                total_seconds += val
            parsed_something = True
        except ValueError:
            print(f"Warning (utils.parse_duration): Invalid numeric value '{value_str}' in duration string: {original_duration_str_for_error_msg}", file=sys.stderr)
            return None

    if not parsed_something:
        if duration_str.isdigit(): 
            try:
                return int(duration_str)
            except ValueError:
                print(f"Warning (utils.parse_duration): Invalid numeric only duration: {original_duration_str_for_error_msg}", file=sys.stderr)
                return None
        print(f"Warning (utils.parse_duration): No valid duration parts found in: '{original_duration_str_for_error_msg}'", file=sys.stderr)
        return None
    
    check_str = duration_str
    for value_str, unit in parts:
        check_str = re.sub(r"\s*" + value_str + r"\s*" + unit + r"\s*", "", check_str, 1)
    
    if check_str.strip(): 
        if not (duration_str.isdigit() and not parts):
            print(f"Warning (utils.parse_duration): Invalid characters or format in duration string: '{original_duration_str_for_error_msg}'. Remainder: '{check_str.strip()}'", file=sys.stderr)
            return None

    return total_seconds if total_seconds > 0 else None


def format_timedelta(td):
    if not isinstance(td, timedelta):
        return ""
    
    total_seconds = int(td.total_seconds())
    if total_seconds < 0: 
        return "0s"

    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts: 
        parts.append(f"{seconds}s")
        
    return "".join(parts) if parts else "0s"
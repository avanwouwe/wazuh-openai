#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request
import urllib.parse
import urllib.error
import os, sys, json, argparse, tempfile, traceback, random, time, glob, ssl
from datetime import datetime, timedelta, timezone

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_PATH = os.path.join(SCRIPT_PATH, 'config.json')
STATE_FILE_PATH = os.path.join(SCRIPT_PATH, 'state.json')
TEMP_LOG_DIR = "/tmp"
STR_ORGID = 'orgId'
STR_API_KEY = 'apiKey'
STR_LAST_TIMESTAMP = 'lastTimestamp'
STR_OPENAI = 'openai'

RESULTS_PER_REQUEST = 100
MAX_API_RETRIES = 5
RESULTS = tempfile.TemporaryFile(mode='w+')
TEMP_LOG_FILE = None

CONFIG = None
org_id = None

parser = argparse.ArgumentParser(description="Export OpenAI audit logs for a given organization.")
parser.add_argument('--unread', '-u', dest='unread', action='store_true',
                   help='export events but keep them marked as unread')
parser.add_argument('--offset', '-o', dest='offset', type=int, default=24,
                   help='maximum number of hours to go back in time')
args = parser.parse_args()


def main():
    global TEMP_LOG_FILE, CONFIG, org_id

    try:
        CONFIG = load_config()
        org_id = dict_path(CONFIG, STR_ORGID)

        os.makedirs(TEMP_LOG_DIR, exist_ok=True)
        cleanup_old_temp_files()

        timestamp = datetime.now().strftime("%s")
        TEMP_LOG_FILE = os.path.join(TEMP_LOG_DIR, f"openai_audit_{timestamp}.log")

        start_time = datetime.now(timezone.utc) - timedelta(hours=args.offset)
        start_timestamp = int(start_time.timestamp())

        state = load_state()
        last_timestamp = validate_timestamp(state.get(STR_LAST_TIMESTAMP, start_timestamp))

        json_msg('extraction started', f'fetching logs since {datetime.fromtimestamp(last_timestamp).isoformat()}')

        try:
            get_logs(last_timestamp)
        except Exception as e:
            warning(f"Log retrieval failed: {str(e)}")
            raise

        if not args.unread:
            try:
                update_state()
            except Exception as e:
                warning(f"State update failed: {str(e)}")
                raise

        print_results()
        json_msg('extraction finished', 'extraction finished')

    except Exception as ex:
        fatal_error(f"Script failed: {str(ex)}")
    finally:
        if 'TEMP_LOG_FILE' in globals() and TEMP_LOG_FILE and os.path.exists(TEMP_LOG_FILE):
            try:
                os.remove(TEMP_LOG_FILE)
            except:
                pass

def validate_timestamp(timestamp):
    try:
        if isinstance(timestamp, str):
            timestamp = int(timestamp)
        if not isinstance(timestamp, int) or timestamp < 0:
            raise ValueError("Invalid timestamp")
        return timestamp
    except:
        return int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp())

def cleanup_old_temp_files():
    try:
        now = time.time()
        for file_path in glob.glob(os.path.join(TEMP_LOG_DIR, "openai_audit_*.log")):
            if os.path.isfile(file_path):
                file_age = now - os.path.getmtime(file_path)
                if file_age > 300:  # 5 minutes
                    os.remove(file_path)
                    json_msg('cleanup', f'deleted old temp file: {file_path}')
    except Exception as e:
        warning(f"cleanup failed: {e}")

def load_config():
    with open(CONFIG_FILE_PATH, 'r') as f:
        return json.load(f)

def load_state():
    if not os.path.exists(STATE_FILE_PATH):
        return {}
    with open(STATE_FILE_PATH, 'r') as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE_PATH + '.tmp', 'w+') as f:
        json.dump(state, f, indent=3)
        f.write("\n")
        os.replace(f.name, STATE_FILE_PATH)

def get_logs(last_timestamp):
    api_key = dict_path(CONFIG, STR_API_KEY)

    base_url = "https://api.openai.com/v1/organization/audit_logs"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    params = {
        "limit": RESULTS_PER_REQUEST,
        "effective_at[gte]": last_timestamp
    }

    events_fetched = 0
    all_events = []
    retries_left = MAX_API_RETRIES

    # Create SSL context with verification disabled
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            # Build URL with parameters
            url = base_url + '?' + urllib.parse.urlencode(params)

            # Create request with headers
            req = urllib.request.Request(url, headers=headers)

            # Make the request with SSL context
            with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
                # Read and parse JSON
                results = json.loads(response.read().decode('utf-8'))

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else 'No error details'
            if retries_left > 0:
                time.sleep(2 ** (MAX_API_RETRIES - retries_left))
                retries_left -= 1
                continue
            else:
                fatal_error(f"HTTP error after retries: {e.code} - {e.reason}: {error_body}")

        except urllib.error.URLError as e:
                fatal_error(f"URL error : {e.reason}")

        except json.JSONDecodeError as e:
                fatal_error(f"JSON parsing error : {e}")

        except Exception as e:
            if retries_left > 0:
                warning(f"API call failed: {str(e)}, retrying... ({retries_left} retries left)")
                time.sleep(2 ** (MAX_API_RETRIES - retries_left))
                retries_left -= 1
                continue
            else:
                fatal_error(f"API error after retries: {str(e)}")

        # Reset retries on successful request
        retries_left = MAX_API_RETRIES

        data = results.get('data', [])
        if not data:
            break

        data.reverse()
        all_events.extend(data)
        events_fetched += len(data)

        if not results.get("has_more"):
            break

        last_event = data[-1]
        last_timestamp = last_event.get("effective_at")
        params["effective_at[gte]"] = last_timestamp

    for ev in all_events:
        write_event(ev)

def write_event(ev):
    """transform minimal fields into Wazuh-style JSON line"""
    try:
        event_id = ev.get("id")
        ev_type = ev.get("type")
        eff_at = ev.get("effective_at")  # seconds since epoch
        eff_dt = datetime.utcfromtimestamp(eff_at).replace(tzinfo=timezone.utc).isoformat()

        actor = dict_path(ev, "actor", "session", "user", "email")
        ip = dict_path(ev, "actor", "session", "ip_address")

        proj_id = dict_path(ev, "project", "id") if "project" in ev else None
        proj_name = dict_path(ev, "project", "name") if "project" in ev else None

        obj_type = '.'.join(ev_type.split('.')[:-1]) if ev_type and '.' in ev_type else None
        obj_id = None
        if ev_type and ev_type in ev:
            obj_id = ev[ev_type].get("id")

        converted = {
            "id": event_id,
            "timestamp": eff_dt,
            "srcip": ip,
            "srcuser": actor,
            STR_OPENAI: {
                "org_id": org_id,
                "project_id": proj_id,
                "project_name": proj_name,
                "type" : ev_type,
                "object_id": obj_id,
                "object_type": obj_type,
                "message": json.dumps(ev)
            }
        }

        json.dump(converted, RESULTS, indent=None)
        RESULTS.write("\n")

        with open(TEMP_LOG_FILE, 'a') as f:
            json.dump(converted, f, indent=None)
            f.write("\n")

    except Exception as e:
        fatal_error(f"failed to parse event: {e}")
def dict_path(d, *path):
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur

def print_results():
    RESULTS.seek(0)
    for line in RESULTS:
        print(line.strip())

def update_state():
    state = load_state()

    RESULTS.seek(0)
    last_timestamp = None

    for line in RESULTS:
        event = json.loads(line)
        if 'timestamp' in event:
            dt = datetime.fromisoformat(event['timestamp'])
            last_timestamp = int(dt.timestamp())

    if last_timestamp:
        state[STR_LAST_TIMESTAMP] = last_timestamp + 1
        save_state(state)

def json_msg(type, message):
    msg = {
        "id": random.randint(0, 99999999999999),
        STR_OPENAI: {
            "org_id": org_id,
            "type": type,
            "message": message
        }
    }
    print(json.dumps(msg))

def fatal_error(message):
    json_msg("extraction error", message)
    sys.exit(0)  # keep 0 for Wazuh

def warning(message):
    json_msg("extraction warning", message)

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        fatal_error("fatal exception :\n" + traceback.format_exc())

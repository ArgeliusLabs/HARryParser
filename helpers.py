import base64
import cgi
import io
import json
import re
import traceback
import urllib.parse
from datetime import datetime

import dns.resolver
import requests
from dateutil import parser


def parse_post_body_code_arguments(input_str):
    if type(input_str) == dict:
        return parse_json_data(input_str)
    if bool(re.match(r'^(\$[\w]+=[^$]*)+$', input_str)):
        # Split the input string into key-value pairs
        key_value_pairs = re.findall(r'\$(\w+)=([^$]*)', input_str)

        # Create a dictionary and decode URL-encoded values
        result_dict = {}
        for key, value in key_value_pairs:
            decoded_value = urllib.parse.unquote(value)
            result_dict[key] = decoded_value
        return result_dict
    return False


def is_base64(s):
    try:
        decoded_bytes = base64.b64decode(s)
        if base64.b64encode(decoded_bytes).decode() == s:
            return True, decoded_bytes
    except Exception:
        pass
    return False, None


def is_hash(s):
    if len(str(s)) <= 64:
        hash_types = {
            r"^[a-fA-F\d]{32}$": "MD5",
            r"^[a-fA-F\d]{40}$": "SHA-1",
            r"^[a-fA-F\d]{64}$": "SHA-256",
        }
        for pattern, hash_type in hash_types.items():
            if re.match(pattern, s):
                return hash_type
    return None


def is_epoch(s):
    # Check if the input string represents an epoch timestamp in seconds or milliseconds
    if re.match(r'^\d{10}(\d{3})?$', s):
        timestamp = int(s[:10])  # Use the first 10 digits as the epoch timestamp in seconds
        return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    return None


def is_date(s):
    epoch_date = is_epoch(s)
    if epoch_date:
        return epoch_date

    # Only attempt to parse strings with typical date separators
    if not re.search(r"[-/:.]", s):
        return None

    try:
        parsed_date = parser.parse(s, fuzzy=True)
        return parsed_date.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return None


def analyze_string(s):
    if type(s) == str and s.strip():
        try:
            is_base64_encoded, decoded_bytes = is_base64(str(s))
            if is_base64_encoded:
                return f"Base64 encoded. Decoded bytes: {decoded_bytes}"

            hash_type = is_hash(str(s))
            if hash_type:
                return f"Hash detected ({hash_type})."
            standardized_date = is_date(str(s))
            if standardized_date:
                return f"Date detected. Standardized date: {standardized_date}"
        except:
            print("exception parsing via analyze string", s)
            traceback.print_exc()
    return False


def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            if v and isinstance(v[0], dict):
                items.extend(flatten_dict(v[0], new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        else:
            try:
                # Check if the value is a JSON string and convert it to a dictionary
                if isinstance(v, str):
                    try:
                        # First, try converting the string to a dictionary
                        v_dict = json.loads(v)
                        if isinstance(v_dict, dict):
                            items.extend(flatten_dict(v_dict, new_key, sep=sep).items())
                        else:
                            items.append((new_key, v))
                    except json.JSONDecodeError:
                        # If the string is not a JSON string, keep it as-is
                        items.append((new_key, v))
                else:
                    items.append((new_key, v))
            except:
                items.append((new_key, v))
    return dict(items)


def parse_multipart_form(mimeType, text, debug=False):
    if debug:
        print(text)

    # Parse the form data using FieldStorage
    form = cgi.FieldStorage(
        fp=io.BytesIO(text.encode()),
        environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': mimeType,
        },
        keep_blank_values=True
    )
    if debug:
        print(form)
    # Get the form fields as a dictionary
    data = {}
    for field in form.keys():
        v = form[field].value
        # Lazy check for possible json
        if "{" in v:
            try:
                v = json.loads(form[field].value)
            except:
                pass
        data[field] = v
    try:
        # Print the extracted data
        if debug:
            print(flatten_dict(data))
        return (flatten_dict(data))
    except:
        print("flatten dict failed on multipart parsing")
        print(data)
        traceback.print_exc()


def fetch_tds(tds_file):
    with open(tds_file, "r") as fin:
        j = json.load(fin)
        return (j.get("domains"))


def remove_illegal_chars(s):
    if type(s) == str:
        return ''.join(c for c in s if ord(c) > 31 or ord(c) == 9 or ord(c) == 10 or ord(c) == 13)
    if type(s) == list:
        return str(s)
    return s


def query_dns_records(domain):
    records = {'A': [], 'CNAME': []}
    for record_type in records.keys():
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for answer in answers:
                records[record_type].append(str(answer.target if record_type == 'CNAME' else answer.address))
        except dns.resolver.NoAnswer:
            pass
    return records


def record_redirects(domain):
    try:
        response = requests.get(f'http://{domain}', allow_redirects=False)
        if response.status_code in (301, 302):
            return response.headers['Location']
    except requests.exceptions.RequestException:
        pass
    return None


def get_redirect_chain(domain):
    redirect_chain = []
    current_domain = domain

    while current_domain:
        next_domain = record_redirects(current_domain)
        if next_domain:
            redirect_chain.append((current_domain, next_domain))
            current_domain = next_domain
        else:
            current_domain = None

    return redirect_chain


def check_domain(domain):
    records = query_dns_records(domain)
    redirect_results = {}

    for record_type, record_values in records.items():
        for value in record_values:
            redirect_chain = get_redirect_chain(value)
            if redirect_chain:
                redirect_results[value] = redirect_chain

    return records, redirect_results


def parse_json_data(text):  # Union[str, Dict, list]) -> Dict[str, Any]:
    if isinstance(text, str):
        try:
            text = json.loads(text)
        except json.JSONDecodeError:
            return {}

    if isinstance(text, list):
        text = text[0]

    return flatten_dict(text) if isinstance(text, dict) else {}

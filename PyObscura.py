import argparse
import re
from datetime import datetime
import os
import sys
import time
import requests
import random
from urllib.parse import urljoin, urlparse
import color  # Assumes a module named 'color' is available for colored output

#############################################
# Dual Template Generation Functions Begin
#############################################

def get_random_user_agent():
    # URL to fetch the JSON list of user agents.
    user_agents_url = "https://jnrbsn.github.io/user-agents/user-agents.json"
    try:
        response = requests.get(user_agents_url)
        response.raise_for_status()  # Raise error for bad responses.
        user_agents = response.json()
        if isinstance(user_agents, list) and user_agents:
            return random.choice(user_agents)
        else:
            raise ValueError("Fetched data is not a valid non-empty list.")
    except Exception as e:
        print(f"Error fetching user agents: {e}")
        return "CustomUserAgent/1.0"

def split_into_chunks(value):
    """
    Splits the value at a semicolon near the middle.
    Returns (chunk1, chunk2) where chunk1 ends with ';' if found.
    """
    mid = len(value) // 2
    split_index = value.rfind(';', 0, mid+1)
    if split_index == -1:
        split_index = value.find(';', mid)
        if split_index == -1:
            split_index = mid
    if value[split_index:split_index+1] == ';':
        return value[:split_index+1], value[split_index+1:]
    else:
        return value[:split_index], value[split_index:]

def fill_template(get_url, response_headers):
    """
    Fills the GET template. Limits the highest header value to 500 bytes,
    removes trailing tokens, replaces chunked Transfer-Encoding, and sanitizes values.
    """
    # Filter out headers with keys containing "date" or "time".
    filtered = {k: v for k, v in response_headers.items() if "date" not in k.lower() and "time" not in k.lower()}
    header_list = list(filtered.items())
    
    def fill_headers(lst, count):
        if len(lst) < count:
            lst.extend([("", "")] * (count - len(lst)))
        return lst[:count]
    
    client_headers = fill_headers(header_list[:2], 2)
    server_headers = fill_headers(header_list[2:], 6)
    
    # Choose the header with the longest value.
    highest_header_value = ""
    for _, value in filtered.items():
        val_str = str(value)
        if len(val_str) > len(highest_header_value):
            highest_header_value = val_str

    # Limit to 500 bytes.
    if len(highest_header_value) > 500:
        highest_header_value = highest_header_value[:500]

    # Remove trailing tokens using your snippet
    tokens = highest_header_value.split(';')
    if len(tokens) > 1:
        if len(tokens) > 3:
            highest_header_value = ';'.join(tokens[:-5]).strip()
        else:
            highest_header_value = ';'.join(tokens[:-4]).strip()
    
    # Split into two chunks
    chunk1, chunk2 = split_into_chunks(highest_header_value)
    
    # Extract path from URL
    parsed = urlparse(get_url)
    uri = parsed.path if parsed.path else "/"
    
    # Unpack client and server headers
    client_header1_key, client_header1_value = client_headers[0]
    client_header2_key, client_header2_value = client_headers[1]
    (server_header1_key, server_header1_value), (server_header2_key, server_header2_value), \
    (server_header3_key, server_header3_value), (server_header4_key, server_header4_value), \
    (server_header5_key, server_header5_value), (server_header6_key, server_header6_value) = server_headers

    # Replace Transfer-Encoding: chunked with X-Device-Type: desktop
    def sanitize_header(key, value):
        key_clean = key.strip().lower()
        value_clean = str(value).strip().lower()
        if key_clean == "transfer-encoding" and value_clean == "chunked":
            return "X-Device-Type", "desktop"
        return key, str(value).replace('=', '-').replace(';', '-').replace('"', '-')

    server_header1_key, server_header1_value = sanitize_header(server_header1_key, server_header1_value)
    server_header2_key, server_header2_value = sanitize_header(server_header2_key, server_header2_value)
    server_header3_key, server_header3_value = sanitize_header(server_header3_key, server_header3_value)
    server_header4_key, server_header4_value = sanitize_header(server_header4_key, server_header4_value)
    server_header5_key, server_header5_value = sanitize_header(server_header5_key, server_header5_value)
    server_header6_key, server_header6_value = sanitize_header(server_header6_key, server_header6_value)


    # Build template
    template = f'''http-get {{
    set verb "POST";
    set uri "{uri}";
    client {{
        header "{client_header1_key}" "{client_header1_value}";
        header "{client_header2_key}" "{client_header2_value}";
        metadata {{
            mask;
            base64url;
            prepend "{chunk1}";
            append "{chunk2}";
            print;
        }}
    }}
    server {{
        output {{
            mask;
            base64url;
            prepend "{chunk1}";
            append "{chunk2}";
            print;
        }}
        header "{server_header1_key}" "{server_header1_value}";
        header "{server_header2_key}" "{server_header2_value}";
        header "{server_header3_key}" "{server_header3_value}";
        header "{server_header4_key}" "{server_header4_value}";
        header "{server_header5_key}" "{server_header5_value}";
        header "{server_header6_key}" "{server_header6_value}";
    }}
}}'''
    return template

def fill_template2(post_uri, response_headers):
    """
    Fills the POST template. Limits the highest header value to 500 bytes,
    removes trailing tokens (using your snippet) if possible, and splits the result into two chunks.
    """
    filtered = {k: v for k, v in response_headers.items() if "date" not in k.lower() and "time" not in k.lower()}
    header_list = list(filtered.items())
    
    def fill_headers(lst, count):
        if len(lst) < count:
            lst.extend([("", "")] * (count - len(lst)))
        return lst[:count]
    
    client_headers = fill_headers(header_list[:4], 4)
    server_headers = fill_headers(header_list[4:], 8)
    
    highest_header_value = ""
    for _, value in filtered.items():
        val_str = str(value)
        if len(val_str) > len(highest_header_value):
            highest_header_value = val_str

    if len(highest_header_value) > 500:
        highest_header_value = highest_header_value[:500]
    # Remove trailing tokens using your snippet:
    tokens = highest_header_value.split(';')
    if len(tokens) > 1:
        if len(tokens) > 3:
            highest_header_value = ';'.join(tokens[:-5]).strip()
        else:
            highest_header_value = ';'.join(tokens[:-4]).strip()
    
    chunk1, chunk2 = split_into_chunks(highest_header_value)
    
    client_header_keys = [client_headers[i][0] for i in range(4)]
    client_header_values = [client_headers[i][1] for i in range(4)]
    server_header_keys = [server_headers[i][0] for i in range(8)]
    server_header_values = [server_headers[i][1] for i in range(8)]
    
    template = f'''http-post {{
    set verb "POST";
    set uri "{post_uri}";
    client {{
        header "{client_header_keys[0]}" "{client_header_values[0]}";
        header "{client_header_keys[1]}" "{client_header_values[1]}";
        id {{
            mask;
            base64url;
            prepend "{chunk1}";
            append "{chunk2}";
            print;
        }}
        output {{
            mask;
            base64url;
            parameter "{client_header_values[0].replace('=', '-').replace(';', '-').replace('"', '-')}";
        }}
    }}
    server {{
        output {{
            mask;
            base64url;
            prepend "{chunk1}";
            append "{chunk2}";
            print;
        }}
        header "{server_header_keys[0]}" "{server_header_values[0].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[1]}" "{server_header_values[1].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[2]}" "{server_header_values[2].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[3]}" "{server_header_values[3].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[4]}" "{server_header_values[4].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[5]}" "{server_header_values[5].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[6]}" "{server_header_values[6].replace('=', '-').replace(';', '-').replace('"', '-')}";
        header "{server_header_keys[7]}" "{server_header_values[7].replace('=', '-').replace(';', '-').replace('"', '-')}";
    }}
}}'''
    return template


def generate_dual_templates(base_url, get_uri, post_uri):
    """
    Sends a GET and a POST request using the base URL, GET URI, and POST URI,
    then returns the filled GET and POST templates along with the full URLs.
    """
    get_url = urljoin(base_url, get_uri)
    post_url = urljoin(base_url, post_uri)
    
    selected_user_agent = get_random_user_agent()
    custom_headers = {
        "User-Agent": selected_user_agent,
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close"
    }
    
    try:
        get_response = requests.get(get_url, headers=custom_headers)
        get_template = fill_template(get_url, get_response.headers)
        
        post_response = requests.post(post_url, headers=custom_headers)
        post_template = fill_template2(post_uri, post_response.headers)
        
        return get_template, post_template, get_url, post_url
    except requests.RequestException as e:
        print(f"An error occurred while generating dual templates: {e}")
        return None

#############################################
# Dual Template Generation Functions End
#############################################

#def replace_template(template_path, output_path, host, sleep, jitter, datajitter, useragent, spawnto, injection, library, syscall, beacongate, forwarder, base_url, geturi, posturi):
def replace_template(template_path, output_path, sleep, jitter, datajitter, useragent, spawnto, injection, library, syscall, beacongate, forwarder, base_url, geturi, posturi):
    # Read the template from the input file.
    with open(template_path, 'r') as file:
        template_content = file.read()

    # Extract the profile name (without file extension) for use in the sample name.
    profile_name = os.path.splitext(os.path.basename(output_path))[0]

    # Define the values to replace.
    values = {
        "Date": datetime.now().strftime("%Y-%m-%d"),
        "name": profile_name,
        #"host": host,
        "sleep": sleep,
        "jitter": jitter,
        "data_jitter": datajitter,
        "user_agent": useragent,
        "spawn_to": spawnto,
        "library": library,
        "injection": injection,
        "forward": forwarder,
        "syscall": syscall
    }

    # Replace each placeholder (e.g. %Date%, %sleep%) with the corresponding value.
    for key, value in values.items():
        placeholder = f"%{key}%"
        template_content = re.sub(re.escape(placeholder), value, template_content)
    
    #######################################
    ## Beacon Gate
    #######################################
    beacon_gate_groups = {
        "Core": ["CloseHandle", "CreateRemoteThread", "CreateThread", "DuplicateHandle", "GetThreadContext", "MapViewOfFile", "OpenProcess", "OpenThread", "ReadProcessMemory", "ResumeThread", "SetThreadContext", "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect", "VirtualProtectEx", "VirtualQuery", "WriteProcessMemory"],
        "Comms": ["InternetOpenA", "InternetConnectA"],
        "CleanUp": ["ExitThread"],
        "All": ["ExitThread", "InternetOpenA", "InternetConnectA","CloseHandle", "CreateRemoteThread", "CreateThread", "DuplicateHandle", "GetThreadContext", "MapViewOfFile", "OpenProcess", "OpenThread", "ReadProcessMemory", "ResumeThread", "SetThreadContext", "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect", "VirtualProtectEx", "VirtualQuery", "WriteProcessMemory"]
    }

    if beacongate in beacon_gate_groups:
        replacements = beacon_gate_groups[beacongate]
    else:
        individual_apis = [api.strip() for api in beacongate.split(',') if api.strip()]
        replacements = individual_apis

    if replacements:
        replacements = list(set(replacements))
        api_replacement_string = ('\t\t\t' + ';\n\t\t\t'.join(replacements) + ';')
        template_content = re.sub(r"%api%", api_replacement_string, template_content)

    #######################################
    ## Dual Template Integration
    #######################################
    dual_templates = generate_dual_templates(base_url, geturi, posturi)
    if dual_templates:
        get_template, post_template, requested_get_url, requested_post_url = dual_templates
        template_content = re.sub(r"%GET%", get_template, template_content)
        template_content = re.sub(r"%POST%", post_template, template_content)
    else:
        print("Failed to generate GET/POST templates.")
    
    #######################################
    ## Status Messages and Write Output
    #######################################
    print(color.yellow("[*] Preparing Variables"))
    time.sleep(0.50)
    print(color.red("[!] Staging is Disabled - Staged Payloads Are Not Available and should not be Used!!"))
    time.sleep(0.50)
    print(color.yellow(f"[*] Post-Ex Process Name: {spawnto}"))
    time.sleep(0.50)
    print(color.yellow(f"[*] Library use for HTTP/HTTPS Traffic: {library}"))
    time.sleep(0.50)
    print(color.yellow(f"[*] Injection method: {injection}"))
    time.sleep(0.50)
    print(color.yellow(f"[*] Syscall Method: {syscall}"))
    time.sleep(0.50)
    print(color.yellow("[*] BeaconGate enabled on these APIs or Groups: " + beacongate))
    
    with open(output_path, 'w') as file:
        file.write(template_content)

    print(color.green(f"File '{output_path}' created with replaced values."))

#############################################
# Main Argument Parsing and Execution
#############################################
banner = r"""
    ____        ____  __                                  
   / __ \__  __/ __ \/ /_  ____________  ___________ _    
  / /_/ / / / / / / / __ \/ ___/ ___/ / / / ___/ __ `/    
 / ____/ /_/ / /_/ / /_/ (__  ) /__/ /_/ / /  / /_/ /     
/_/    \__, /\____/_.___/____/\___/\__,_/_/   \__,_/      
      /____/            
      
****************************************************
*                                                  *
*        Cobalt Strike C2 profile Generator        *
*                      v1.0                        *
*                 Author: dmcxblue                 *
*                                                  *
****************************************************
"""

if "--help" in sys.argv or "-h" in sys.argv:
    print(color.green(banner))

parser = argparse.ArgumentParser(
    description="Use this tool to build customized C2 profiles.",
    epilog="Thank you for using the C2 Profile Builder!",
    formatter_class=argparse.RawDescriptionHelpFormatter
)

# parser.add_argument("--inprofile", required=True, help="Path to the input profile template file.")
parser.add_argument("--outprofile", required=True, help="Path to the output profile file.")
# parser.add_argument("--host", required=True, help="Team Server Domain name")
parser.add_argument("--sleep", required=True, help="Sleep time in milliseconds.")
parser.add_argument("--jitter", required=True, help="Jitter time.")
parser.add_argument("--datajitter", required=False, default="50", help="Data Jitter time. [Default 50]")
parser.add_argument("--useragent", required=False, default=get_random_user_agent(), help="Beacon User Agent. [Default: Randomized]")
parser.add_argument("--spawnto", required=False, default="rundll32", help="Spawn to Binary for PostEx.")
parser.add_argument("--injection", required=False, default="VirtualAllocEx", help="VirtualAllocEx, NtMapViewOfSection [Default: VirtualAllocEx]")
parser.add_argument("--library", required=False, default="winhttp", help="Select the default HTTP Beacon library (wininet, winhttp) [Default: winhttp]")
parser.add_argument("--syscall", required=False, default="Indirect", help="Defines the ability to use direct/indirect system calls [Default: None] Example: Direct, Indirect, None")
parser.add_argument("--beacongate", required=False, default="All", help="APIs which beacon gate will work on [--beacongate ExitThread *Individually | --beacongate Core *By Groups], [Default: All]")
parser.add_argument("--forwarder", required=False, default="false", help="Enabled the X-forwarded-For header (If you are using Relay and are behind a proxy set to True)")
parser.add_argument("--url", required=True, default="https://www.microsoft.com/", help="URL to query for HTTP response")
parser.add_argument("--geturi", required=True, default="/en-us/windows", help="Directory from main url for GET, e.g., /about")
parser.add_argument("--posturi", required=True, default="/en-us/windows/get-windows-11", help="Directory from main url for POST, e.g., /contact")

try:
    args = parser.parse_args()
except Exception as e:
    print(f"Error parsing arguments: {e}")
    parser.print_help()
    exit(1)

#replace_template(args.inprofile, args.outprofile, args.host, args.sleep, args.jitter, args.datajitter, args.useragent, args.spawnto, args.injection, args.library, args.syscall, args.beacongate, args.forwarder, args.url, args.geturi, args.posturi)
# replace_template("sample.profile", args.outprofile, args.host, args.sleep, args.jitter, args.datajitter, args.useragent, args.spawnto, args.injection, args.library, args.syscall, args.beacongate, args.forwarder, args.url, args.geturi, args.posturi)

replace_template("sample.profile", args.outprofile, args.sleep, args.jitter, args.datajitter, args.useragent, args.spawnto, args.injection, args.library, args.syscall, args.beacongate, args.forwarder, args.url, args.geturi, args.posturi)





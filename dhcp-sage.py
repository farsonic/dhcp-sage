import requests
import argparse
import json
import yaml
import os
import textwrap
import re
from tabulate import tabulate
import google.generativeai as genai

# --- Constants ---
BASE_PATH = "/rest/ip/dhcp-server/lease"
BRIDGE_HOST_PATH = "/rest/interface/bridge/host"
INTERFACE_PATH = "/rest/interface"
CONFIG_DEFAULT = "config.yaml"
OUI_LOOKUP_URL = "https://api.macvendors.com/"
OUI_CACHE_FILE = "oui_cache.json"
WRAP_WIDTH = 90

# --- Global Cache ---
OUI_CACHE = {}

# --- Corrected Function to Substitute Environment Variables ---
def substitute_env_vars(config_item):
    """Recursively substitutes ${VAR_NAME} placeholders in a config item."""
    if isinstance(config_item, dict):
        return {k: substitute_env_vars(v) for k, v in config_item.items()}
    elif isinstance(config_item, list):
        return [substitute_env_vars(i) for i in config_item]
    elif isinstance(config_item, str):
        # Find all ${VAR_NAME} patterns and replace them with the env var value,
        # or an empty string if the env var is not set.
        return re.sub(r'\$\{(\w+)\}', lambda m: os.getenv(m.group(1), ''), config_item)
    else:
        # Return other data types (int, bool, etc.) as-is
        return config_item


def load_config(path):
    """Loads configuration from a YAML file and substitutes env vars."""
    if not os.path.isfile(path):
        print(f"⚠️  Config file not found: {path}. Relying on environment variables.")
        return {}
    try:
        with open(path) as f:
            config = yaml.safe_load(f)
        # Substitute environment variables after loading
        return substitute_env_vars(config) if config else {}
    except Exception as e:
        print(f"Error loading or parsing config file: {e}")
        return {}


def load_oui_cache():
    """Loads the OUI vendor cache from a local JSON file."""
    global OUI_CACHE
    if os.path.isfile(OUI_CACHE_FILE):
        try:
            with open(OUI_CACHE_FILE, 'r') as f:
                OUI_CACHE = json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️  Warning: Could not decode OUI cache file at {OUI_CACHE_FILE}. Starting fresh.")
            OUI_CACHE = {}


def save_oui_cache():
    """Saves the OUI vendor cache to a local JSON file."""
    with open(OUI_CACHE_FILE, 'w') as f:
        json.dump(OUI_CACHE, f, indent=2)


def get_api_data(base_url, auth, path):
    """Generic function to fetch data from the MikroTik API."""
    try:
        if not base_url or "://" not in base_url:
            raise ValueError("Invalid base_url provided.")
        r = requests.get(f"{base_url}{path}", auth=auth, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Error fetching {path}: {e}")
        return [] if path.endswith('s') else {}


def find_lease_by_mac(leases, mac):
    """Finds a specific lease entry by its MAC address."""
    mac = mac.lower()
    for lease in leases:
        if lease.get("mac-address", "").lower() == mac:
            return lease
    return None


def lookup_oui(mac):
    """Looks up the vendor of a MAC address, using a local cache first."""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    if prefix in OUI_CACHE:
        return OUI_CACHE[prefix]

    try:
        r = requests.get(f"{OUI_LOOKUP_URL}{prefix}")
        if r.status_code == 200:
            vendor = r.text
            OUI_CACHE[prefix] = vendor
            save_oui_cache()
            return vendor
    except requests.exceptions.RequestException:
        return "Lookup Failed"
    return "Unknown"


def classify_device(hostname):
    """Provides a simple classification based on the device's hostname."""
    if not hostname:
        return "Generic Network Device"
    hostname = hostname.lower()
    rules = {
        "Apple Mobile": ["iphone", "ipad"],
        "Samsung Mobile": ["samsung"],
        "Home Automation": ["homeassistant", "shelly", "sonoff"],
        "Printer": ["printer", "print"],
        "Smart TV": ["tv", "bravia", "vizio"],
        "Camera": ["camera", "cam"],
        "Smart Plug": ["plug", "socket"],
        "Network Switch": ["switch"],
        "Computer": ["desktop", "laptop", "pc"]
    }
    for device_type, keywords in rules.items():
        if any(keyword in hostname for keyword in keywords):
            return device_type
    return "Generic Network Device"


def generate_summary_table(device):
    """Prints a formatted summary table for a single device."""
    headers = ["Field", "Value"]
    rows = [
        ["Label", device.get("comment", "")],
        ["MAC Address", device["mac"]],
        ["IP Address", device["ip"]],
        ["Hostname", device["hostname"]],
        ["Interface", device["interface"]],
        ["Vendor", device["vendor"]],
        ["Device Type", device["description"]],
        ["Status", device["status"]],
        ["Static", device["static"]],
        ["Last Seen", device["last_seen"]],
    ]
    print(tabulate(rows, headers=headers, tablefmt="github"))


def format_ai_response(raw_text):
    """Takes raw text from an AI and applies consistent formatting rules."""
    command_separator = "---COMMANDS---"
    cleaned_response = raw_text.replace('*', '').replace('`', '')

    if command_separator in cleaned_response:
        analysis_part, command_part = cleaned_response.split(command_separator, 1)
        paragraphs = analysis_part.strip().split('\n\n')
        wrapped_paragraphs = [textwrap.fill(p, width=WRAP_WIDTH) for p in paragraphs]
        formatted_analysis = '\n\n'.join(wrapped_paragraphs)
        return f"{formatted_analysis}\n\n{command_part.strip()}\n"
    else:
        # Fallback for older prompts or unexpected formats
        paragraphs = cleaned_response.strip().split('\n\n')
        wrapped_paragraphs = [textwrap.fill(p, width=WRAP_WIDTH) for p in paragraphs]
        return '\n\n'.join(wrapped_paragraphs)


def enrich_with_openai_summary(api_key, prompt_template, device, model_name):
    """Calls OpenAI API and formats the response."""
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        context = prompt_template.format(**device)
        data = { "model": model_name, "messages": [{"role": "user", "content": context}] }
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, data=json.dumps(data))
        r.raise_for_status()
        response_text = r.json()['choices'][0]['message']['content']
        return format_ai_response(response_text)
    except Exception as e:
        return f"(OpenAI summary failed: {e})"


def enrich_with_gemini_summary(api_key, prompt_template, device, model_name):
    """Calls Gemini API and formats the response."""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        context = prompt_template.format(**device)
        response = model.generate_content(context)
        return format_ai_response(response.text)
    except Exception as e:
        return f"(Gemini summary failed: {e})"


def make_static(base_url, auth, lease_id):
    """Converts a dynamic DHCP lease to a static one."""
    r = requests.post(f"{base_url}{BASE_PATH}/make-static", auth=auth, headers={"content-type": "application/json"}, data=json.dumps({"numbers": lease_id}), verify=False)
    r.raise_for_status()
    return r.json() if r.content else {}


def update_comment(base_url, auth, lease_id, comment):
    """Updates the comment for a DHCP lease."""
    r = requests.patch(f"{base_url}{BASE_PATH}/{lease_id}", auth=auth, headers={"content-type": "application/json"}, data=json.dumps({"comment": comment}), verify=False)
    r.raise_for_status()
    return r.json() if r.content else {}


def delete_lease(base_url, auth, lease_id):
    """Deletes a DHCP lease."""
    r = requests.delete(f"{base_url}{BASE_PATH}/{lease_id}", auth=auth, verify=False)
    r.raise_for_status()
    return True


def show_mac_summary(base_url, auth, mac, use_ai=False, ai_provider='openai', api_key=None, model_name=None, prompt_template="", notes=None, json_output=False):
    """Gathers and displays a detailed summary for a specific MAC address."""
    leases = get_api_data(base_url, auth, BASE_PATH)
    lease = find_lease_by_mac(leases, mac)
    if not lease:
        print(f"❌ No lease found for MAC {mac}")
        return

    bridge_hosts = get_api_data(base_url, auth, BRIDGE_HOST_PATH)
    interfaces = get_api_data(base_url, auth, INTERFACE_PATH)
    
    bridge_map = {e["mac-address"].upper(): e["interface"] for e in bridge_hosts if "mac-address" in e}
    iface_comments = {entry["name"]: entry.get("comment", entry["name"]) for entry in interfaces if "name" in entry}

    iface = bridge_map.get(mac.upper(), "N/A")
    iface_desc = iface_comments.get(iface, iface)
    hostname = lease.get("host-name", "N/A")

    device = {
        "mac": mac, "ip": lease.get("address", "N/A"), "hostname": hostname,
        "comment": lease.get("comment", ""), "interface": iface_desc, "vendor": lookup_oui(mac),
        "status": lease.get("status", "N/A"), "static": "no" if lease.get("dynamic", "true") == "true" else "yes",
        "last_seen": lease.get("last-seen", "N/A"), "description": classify_device(hostname),
        "notes": notes or "Not provided."
    }

    if json_output:
        print(json.dumps(device, indent=2))
        return

    print("\n### Device Summary\n")
    generate_summary_table(device)

    if use_ai and api_key and prompt_template:
        print(f"\n### AI Contextual Analysis (using {ai_provider}/{model_name})")
        summary = ""
        if ai_provider == 'gemini':
            summary = enrich_with_gemini_summary(api_key, prompt_template, device, model_name)
        else: # Default to openai
            summary = enrich_with_openai_summary(api_key, prompt_template, device, model_name)
        print(summary)


def list_leases(base_url, auth, bound=None, search_query=None, json_output=False):
    """Lists DHCP leases, with options for filtering, searching, and JSON output."""
    leases = get_api_data(base_url, auth, BASE_PATH)
    bridge_hosts = get_api_data(base_url, auth, BRIDGE_HOST_PATH)
    interfaces = get_api_data(base_url, auth, INTERFACE_PATH)

    bridge_map = {e["mac-address"].upper(): e["interface"] for e in bridge_hosts if "mac-address" in e}
    iface_comments = {entry["name"]: entry.get("comment", entry["name"]) for entry in interfaces if "name" in entry}

    all_devices = []
    for lease in leases:
        mac = lease.get("mac-address", "")
        iface = bridge_map.get(mac.upper(), "N/A")
        iface_desc = iface_comments.get(iface, iface)
        all_devices.append({
            "comment": lease.get("comment", ""), "address": lease.get("address", ""), "mac-address": mac,
            "vendor": lookup_oui(mac), "host-name": lease.get("host-name", ""), "interface": iface_desc,
            "server": lease.get("server", ""), "status": lease.get("status", ""),
            "static": "no" if lease.get("dynamic", "true") == "true" else "yes", "last-seen": lease.get("last-seen", "")
        })
    
    filtered_devices = all_devices
    if bound:
        filtered_devices = [d for d in filtered_devices if d['status'] == bound]

    if search_query:
        try:
            key, value = search_query.split('=', 1)
            key, value = key.strip().lower(), value.strip().lower()
            
            search_key_map = {"comment": "comment", "ip": "address", "mac": "mac-address", "hostname": "host-name", "interface": "interface", "vendor": "vendor"}
            internal_key = search_key_map.get(key)
            
            if internal_key:
                filtered_devices = [d for d in filtered_devices if value in d.get(internal_key, "").lower()]
            else:
                print(f"⚠️ Invalid search key: '{key}'. Valid keys are: {', '.join(search_key_map.keys())}")
        except ValueError:
            print("⚠️ Invalid search format. Use KEY=VALUE (e.g., 'hostname=my-phone').")

    if not filtered_devices:
        print("No leases found matching the criteria.")
        return

    if json_output:
        print(json.dumps(filtered_devices, indent=2))
    else:
        headers = list(filtered_devices[0].keys())
        table_data = [list(d.values()) for d in filtered_devices]
        print(tabulate(table_data, headers=[h.upper().replace('-', ' ') for h in headers], tablefmt="github"))


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(description="DHCP Sage: AI-powered MikroTik DHCP Client")
    parser.add_argument("--host", help="Router IP address or hostname")
    parser.add_argument("--username", help="Router username")
    parser.add_argument("--password", help="Router password")
    parser.add_argument("--config", default=CONFIG_DEFAULT, help=f"Path to config file (default: {CONFIG_DEFAULT})")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS for the connection")

    parser.add_argument("--list", action="store_true", help="List all DHCP leases")
    parser.add_argument("--mac", help="Specify a MAC address for an action")
    
    parser.add_argument("--bound", action="store_true", help="Filter for 'bound' leases only")
    parser.add_argument("--waiting", action="store_true", help="Filter for 'waiting' leases only")
    parser.add_argument("--search", help="Search leases (e.g., --search 'hostname=iphone')")

    parser.add_argument("--set-static", action="store_true", help="Make the lease for the specified MAC static")
    parser.add_argument("--comment", help="Set a comment for the specified MAC address")
    parser.add_argument("--delete", action="store_true", help="Delete the lease for the specified MAC")

    parser.add_argument("--ai", action="store_true", help="Show AI-powered summary for a MAC address")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--provider", choices=['openai', 'gemini'], help="Specify AI provider")
    parser.add_argument("--model", help="Specify AI model to use (e.g., gpt-4o)")
    parser.add_argument("--notes", help="Add custom notes to the AI prompt for additional context")
    
    args = parser.parse_args()

    config = load_config(args.config)

    # Precedence: command-line arg > config file (which may use env vars)
    host = args.host or config.get("host")
    username = args.username or config.get("username")
    password = args.password or config.get("password")
    use_ssl = args.ssl or config.get("ssl", False)
    
    ai_provider = args.provider or config.get("ai_provider", "openai")

    if ai_provider == 'gemini':
        api_key = config.get("gemini_api_key")
        default_model = config.get("gemini_model", "gemini-1.5-flash-latest")
    else: # Default to openai
        api_key = config.get("openai_api_key")
        default_model = config.get("openai_model", "gpt-4")

    model_name = args.model or default_model
    prompt_template = config.get("ai_prompt", "")

    if not all([host, username, password]):
        print("❌ Host, username, and password are required. Provide them via arguments or a config file that references environment variables.")
        return

    protocol = "https" if use_ssl else "http"
    base_url = f"{protocol}://{host}"
    auth = (username, password)
    
    load_oui_cache()

    try:
        if args.list:
            filter_status = "bound" if args.bound else "waiting" if args.waiting else None
            list_leases(base_url, auth, bound=filter_status, search_query=args.search, json_output=args.json)
        elif args.mac:
            lease_to_modify = find_lease_by_mac(get_api_data(base_url, auth, BASE_PATH), args.mac)
            if not lease_to_modify and (args.set_static or args.comment or args.delete):
                 print(f"❌ MAC address {args.mac} not found in leases. Cannot perform action.")
                 return
            
            lease_id = lease_to_modify.get(".id") if lease_to_modify else None

            if args.set_static:
                print(f"Converting {args.mac} to a static lease...")
                make_static(base_url, auth, lease_id)
                print("✅ Done.")

            if args.comment is not None:
                print(f"Setting comment on {args.mac} to '{args.comment}'...")
                update_comment(base_url, auth, lease_id, args.comment)
                print("✅ Done.")

            if args.delete:
                print(f"Deleting lease for {args.mac}...")
                delete_lease(base_url, auth, lease_id)
                print("✅ Done.")
                return

            if not any([args.set_static, args.comment is not None, args.delete]):
                show_mac_summary(base_url, auth, args.mac, use_ai=args.ai, ai_provider=ai_provider, api_key=api_key, model_name=model_name, prompt_template=prompt_template, notes=args.notes, json_output=args.json)
        else:
            parser.print_help()
    except requests.HTTPError as e:
        print(f"❌ HTTP error: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    main()

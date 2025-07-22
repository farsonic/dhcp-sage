# Mikrotik DHCP Sage

### *Wise counsel for your MikroTik network.*

DHCP Sage is an AI-powered command-line tool for managing and analyzing DHCP leases on a MikroTik router. It goes beyond simple lease management by using generative AI (from either OpenAI or Google Gemini) to provide deep, contextual analysis of network devices, helping you identify unknown hardware, assess security risks, and make informed configuration decisions.

<a href="https://buymeacoffee.com/farsonic" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px; width: 217px;" ></a>

---

## Features

- **List & Search Leases**: View all DHCP leases or search for specific devices by hostname, IP, MAC address, or vendor.
- **AI-Powered Analysis**: Get a detailed, human-readable summary of any device on your network. The AI can identify the device's purpose, assess its security posture, and recommend configuration changes.
- **Actionable Commands**: The AI automatically generates the precise shell commands needed to implement its recommendations (e.g., setting a static IP, updating a comment, or deleting a stale lease).
- **Dual AI Provider Support**: Choose between using OpenAI (e.g., GPT-4o) or Google (e.g., Gemini 1.5 Pro) as your analysis engine.
- **Secure Configuration**: Keep your secrets safe. All sensitive information (passwords, API keys) is loaded from environment variables, so you never have to hardcode them in your config file.
- **Vendor Lookup Caching**: Fast OUI lookups with a local cache to minimize external API calls and speed up execution.

---

## Installation

Follow these steps to get DHCP Sage running on your local machine.

### 1. Clone the Repository

```bash
git clone https://github.com/farsonic/dhcp-sage
cd dhcp-sage
```

### 2. Set Up a Virtual Environment

It's highly recommended to use a Python virtual environment to manage dependencies.

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

Install the required Python libraries using the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

---

## Configuration

DHCP Sage is configured using a `config.yaml` file and environment variables.

### 1. Create `config.yaml`

Edit the config.yaml file if reequired. The only real things that need to be changed in here is the entries for host, passwords and API keys if you are hardcoding them, otherwise it will leverage ENV entries for thess. You should also specify the AI provider you want to use and the specific model. I've really only tested with Gemini and briefly with ChatGPT. 

### 2. Set Environment Variables

Before running the script, you must set the following environment variables in your terminal. This keeps your credentials secure and out of the codebase.

```bash
# MikroTik Credentials
export MIKROTIK_HOST="192.168.0.1"
export MIKROTIK_USERNAME="your_admin_username"
export MIKROTIK_PASSWORD="your_router_password"

# AI Provider API Keys
export OPENAI_API_KEY="your_openai_api_key_here"
export GEMINI_API_KEY="your_gemini_api_key_here"
```

Note: These variables are only set for the current terminal session. To make them permanent, add them to your shell's profile script (e.g., `~/.zshrc`, `~/.bash_profile`).

---

## Usage

Here are some examples of how to use DHCP Sage:

### List All Leases
(filter with --bound or --waiting) 

```bash
python3 dhcp-sage.py --list 
```

<img width="1519" height="616" alt="Screenshot 2025-07-22 at 12 26 34 pm" src="https://github.com/user-attachments/assets/00d3799d-d3c5-408c-b544-9311ff8bc061" />



### Get an AI Analysis for a Device
This will pass all known details about this MAC address to either ChatGPT or Gemini for Analysis and return a summary of information. 

```bash
python3 dhcp-sage.py --mac 68:EC:8A:0B:EC:4A --ai
```

### Get an AI Analysis for a Device and have AI determine a functional comment for the device based on Catagory, Function and Name. This is for a specific MAC address only. 

```bash
python3 dhcp-sage.py  --mac 68:EC:8A:0B:EC:4A --ai --auto-apply
```

### Get an AI Analysis for a Device and have AI determine a functional comment for the device based on Catagory, Function and Name. You can use the --only-uncommented option to automatically apply this to every bound DHCP entry that doesn't have a comment. This will ignore entries that have an existing comment. 

```bash
python3 dhcp-sage.py  --ai --auto-apply --only-uncommented
```

### Provide Extra Context to the AI

```bash
python3 dhcp-sage.py --mac 68:EC:8A:0B:EC:4A --ai --notes "I think this is my new smart hub in the living room."
```

### Use a Specific AI Provider or Model

```bash
python3 dhcp-sage.py --mac 68:EC:8A:0B:EC:4A --ai --provider openai --model gpt-4o
```

### Set a Comment

```bash
python3 dhcp-sage.py --mac 68:EC:8A:0B:EC:4A --comment "Living Room Smart Hub"
```

### Make a Lease Static

```bash
python3 dhcp-sage.py --mac 68:EC:8A:0B:EC:4A --set-static
```

### Delete a Lease

```bash
python3 dhcp-sage.py --mac 68:EC:8A:0B:EC:4A --delete
```

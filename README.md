# DHCP Sage

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
First, clone the project from GitHub:
```bash
git clone <your-github-repo-url>
cd <your-project-directory>


2. Set Up a Virtual Environment
It's highly recommended to use a Python virtual environment to manage dependencies.
python3 -m venv venv
source venv/bin/activate


3. Install Dependencies
Install the required Python libraries using the requirements.txt file.
pip install -r requirements.txt


Configuration
DHCP Sage is configured using a config.yaml file and environment variables.
1. Create config.yaml
Create a config.yaml file in the root of the project directory. You can use the example below as a template. This file is safe to commit to Git as it contains no secrets.
# config.yaml

# --- MikroTik Router Configuration ---
# These values will be read from environment variables.
host: ${MIKROTIKE_HOST}
username: ${MIKROTIK_USERNAME}
password: ${NIKROTIK_PASSWORD}

# --- AI Configuration ---
# Set your default provider: 'openai' or 'gemini'
ai_provider: gemini

# API Keys will be read from environment variables.
openai_api_key: ${OPENAI_API_KEY}
gemini_api_key: ${GEMINI_API_KEY}

# Set your preferred default models for each provider.
# These can be overridden with the --model flag.
gemini_model: "gemini-1.5-pro-latest"
openai_model: "gpt-4-turbo"

# --- AI Prompt ---
# This is the master prompt that guides the AI's analysis.
ai_prompt: >
  You are a senior network security and performance analyst. Your task is to provide a comprehensive and actionable analysis of a network device using the following data. Your response must be structured with the headings provided below.

  **Device Data:**
  - MAC: {mac}
  - IP: {ip}
  - Hostname: {hostname}
  - Label: {comment}
  - Vendor: {vendor}
  - Interface: {interface}
  - Device Type: {description}
  - Status: {status}
  - Static: {static}
  - Last Seen: {last_seen}
  - User Notes: {notes}

  **Analysis & Recommendations:**

  **1. Executive Summary:**
  Provide a detailed, plain-English summary of what this device is.

  **2. Security Assessment:**
  Analyze the device from a security perspective.

  **3. Configuration Recommendation:**
  - **Static IP:** State "Yes" or "No". Justify your answer.
  - **Device Label:** Suggest an improved, descriptive label.

  **4. Housekeeping Action:**
  Recommend a single, clear action: KEEP, INVESTIGATE, or REMOVE.

  **5. Confidence Score:**
  Provide a score from 1 to 5 and briefly explain your reasoning.
  
  ---COMMANDS---
  
  **6. Actionable Commands:**
  
  **Warning:** Only execute these commands if you understand their purpose and how to use them. Misuse can interrupt network functionality.
  
  **RULES FOR GENERATING COMMANDS:**
  - **NEVER** use backticks, asterisks, or any markdown formatting for the commands.
  - **EACH COMMAND MUST BE ON ITS OWN SEPARATE LINE.**
  
  - **IF** your recommendation in section 4 is 'REMOVE', THEN ONLY generate this single, exact line:
  `python3 dhcp_sage.py --mac {mac} --delete`
  
  - **ELSE (if the recommendation is not REMOVE):**
    - **IF** the 'Static' status in the data is 'no' AND your recommendation in section 3 was 'Yes', THEN generate this exact line:
    `python3 dhcp_sage.py --mac {mac} --set-static`
    
    - **IF** you suggested a new 'Device Label' in section 3 that is different from the current 'Label', THEN generate this exact line:
    `python3 dhcp_sage.py --mac {mac} --comment "Your new suggested label"`


2. Set Environment Variables
Before running the script, you must set the following environment variables in your terminal. This keeps your credentials secure and out of the codebase.
# MikroTik Credentials
export MIKROTIKE_HOST="192.168.0.254"
export MIKROTIK_USERNAME="your_admin_username"
export NIKROTIK_PASSWORD="your_router_password"

# AI Provider API Keys
export OPENAI_API_KEY="your_openai_api_key_here"
export GEMINI_API_KEY="your_gemini_api_key_here"


Note: These variables are only set for the current terminal session. To make them permanent, add them to your shell's profile script (e.g., ~/.zshrc, ~/.bash_profile).
Usage
Here are some examples of how to use DHCP Sage.
List All Leases
python3 dhcp_sage.py --list


Get an AI Analysis for a Device
To get a full AI-powered report on a specific device:
python3 dhcp_sage.py --mac 68:EC:8A:0B:EC:4A --ai


Provide Extra Context to the AI
Use the --notes flag to give the AI more context for its analysis.
python3 dhcp_sage.py --mac 68:EC:8A:0B:EC:4A --ai --notes "I think this is my new smart hub in the living room."


Use a Specific AI Provider or Model
Override the defaults set in your config.yaml for a single run.
# Use OpenAI's gpt-4o model for this query
python3 dhcp_sage.py --mac 68:EC:8A:0B:EC:4A --ai --provider openai --model gpt-4o


Set a Comment
Directly set a comment on a lease without running the AI analysis.
python3 dhcp_sage.py --mac 68:EC:8A:0B:EC:4A --comment "Living Room Smart Hub"


Make a Lease Static
python3 dhcp_sage.py --mac 68:EC:8A:0B:EC:4A --set-static


Delete a Lease
python3 dhcp_sage.py --mac 68:EC:8A:0B:EC:4A --delete




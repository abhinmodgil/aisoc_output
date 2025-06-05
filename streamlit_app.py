# app.py

import streamlit as st
import requests
import base64
import re
import pandas as pd
import json

# --- GitHub Configuration ---
GITHUB_USERNAME = "abhinmodgil"
GITHUB_REPO_NAME = "aisoc_output" # This MUST be a PUBLIC repository
GITHUB_BRANCH = "main"
ALERTS_DATA_BASE_PATH = "outputs/alerts"
WAZUH_ALERTS_FILE_PATH = "jan30_alerts.json"

# GH_TOKEN_FOR_REQUESTS is removed for public deployment without explicit PAT
# Unauthenticated requests will be used. Ensure GITHUB_REPO_NAME is public.

st.info(
    "ℹ️ This app is configured for public GitHub access without a PAT. "
    f"Ensure the target repository '{GITHUB_USERNAME}/{GITHUB_REPO_NAME}' is public. "
    "API rate limits for unauthenticated requests will apply."
)

# --- GitHub Helper Functions (Modified to not require token explicitly in signature) ---
@st.cache_data(ttl=300)
def list_github_directories(username, repo, path, branch): # Removed token from signature
    """Lists directories from a public GitHub repository path."""
    api_url = f"https://api.github.com/repos/{username}/{repo}/contents/{path.strip('/')}?ref={branch}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    # No Authorization header added if token is not provided
    dir_names = []
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        contents = response.json()
        if isinstance(contents, list):
            for item in contents:
                if item["type"] == "dir": dir_names.append(item["name"])
        else:
            st.warning(f"Unexpected content for path '{path}'. Expected list. Got: {type(contents)}")
    except requests.exceptions.HTTPError as http_err:
        st.error(f"HTTP error listing dirs for '{path}': {http_err} (Is the repo public and path correct?)")
    except Exception as e:
        st.error(f"Error listing dirs for '{path}': {e}")
    return sorted(dir_names)


@st.cache_data(ttl=300)
def get_github_file_content(username, repo, file_path, branch): # Removed token from signature
    """Fetches and decodes file content from a public GitHub file_path via API."""
    api_url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path.strip('/')}?ref={branch}"
    headers_api = {"Accept": "application/vnd.github.v3+json"}
    # No Authorization header added
    try:
        response_api = requests.get(api_url, headers=headers_api)
        response_api.raise_for_status()
        content_data = response_api.json()
        if "content" in content_data:
            base64_content_cleaned = content_data["content"].replace('\n', '').replace('\r', '')
            decoded_bytes = base64.b64decode(base64_content_cleaned)
            return decoded_bytes.decode('utf-8')
        else:
            st.error(f"No 'content' in API response for '{file_path}'. JSON: {content_data}"); return None
    except requests.exceptions.HTTPError as http_err:
        if response_api.status_code == 404:
            return None
        st.error(f"HTTP error getting file '{file_path}': {http_err} (Is the repo public and path correct?)")
    except Exception as e:
        st.error(f"Error getting file '{file_path}': {e}")
    return None


# --- Data Loading Functions (Calls to helpers are modified) ---
@st.cache_data(ttl=3600)
def load_wazuh_alerts_data_from_github(username, repo, file_path, branch): # Removed token
    json_lines_content_str = get_github_file_content(username, repo, file_path, branch) # No token passed

    if json_lines_content_str:
        alerts_dict = {}
        error_messages_list = []
        for i, line in enumerate(json_lines_content_str.strip().split('\n')):
            line = line.strip()
            if not line: continue
            try:
                alert_obj = json.loads(line)
                alert_id_val = alert_obj.get("id")
                if alert_id_val:
                    alerts_dict[str(alert_id_val)] = alert_obj
                else:
                    error_messages_list.append(
                        f"Line {i + 1}: Alert object missing 'id' field. Content: '{line[:100]}...'")
            except json.JSONDecodeError as e:
                error_messages_list.append(f"Line {i + 1}: Error decoding JSON: {e}. Content: '{line[:100]}...'")
        combined_error_message = "\n".join(error_messages_list) if error_messages_list else None
        if alerts_dict:
            return alerts_dict, combined_error_message, json_lines_content_str if combined_error_message else None
        elif combined_error_message:
            return None, combined_error_message, json_lines_content_str
        elif json_lines_content_str.strip(): # Content exists but no valid alerts parsed
            return None, f"No alerts with 'id' fields found or processed from '{file_path}'. Check JSON Lines structure.", json_lines_content_str
        else: # File was empty or only whitespace
            return None, f"The Wazuh alerts file '{file_path}' appears to be empty or only whitespace.", None
    else:
        return None, f"Could not retrieve content for Wazuh alerts file: '{file_path}' from public repo.", None


# --- Parsing Functions (No changes needed here) ---
def parse_phase1_ioc_file_content(raw_text):
    iocs_data = {};
    validated_count_str = "N/A"
    if not raw_text: return iocs_data, validated_count_str
    pattern_for_validated_count = r"✅\s*Parsed and validated\s*(\d+)\s*unique IOC keys?(?:\([a-zA-Z]*\))?\.?"
    try:
        validated_message_match = re.search(pattern_for_validated_count, raw_text, re.IGNORECASE)
        if validated_message_match: validated_count_str = validated_message_match.group(1)
    except re.error as e:
        st.warning(f"Regex error for P1 validated count: {e}")
    validated_iocs_block_match = re.search(r"Validated IOCs:\s*\n(.*?)(?=\n\n---|\Z)", raw_text, re.DOTALL)
    current_section_to_parse = ""
    if validated_iocs_block_match:
        current_section_to_parse = validated_iocs_block_match.group(1).strip()
    else:
        actual_iocs_match = re.search(
            r"--- Extracted IOCs and Entities \(Original Raw LLM Output from IOC Extractor\) ---\s*\n(.*?)(?:\n--- END ---|\n------------------------------------------------------------------------------------|\Z)",
            raw_text, re.DOTALL)
        if actual_iocs_match:
            current_section_to_parse = actual_iocs_match.group(1).strip()
        else:
            current_section_to_parse = raw_text.strip()
    ioc_line_pattern = re.compile(r"^\s*([^:]+?)\s*:\s*(.+)$")
    lines = current_section_to_parse.split('\n')
    if not lines and current_section_to_parse: lines = [current_section_to_parse]
    for line in lines:
        line = line.strip();
        if not line or line.startswith("---") or line.startswith("Extracted IOCs and Entities:"): continue
        match = ioc_line_pattern.match(line)
        if match:
            key, value = match.group(1).strip(), match.group(2).strip()
            if key and value:
                if key in iocs_data:
                    if isinstance(iocs_data[key], list):
                        iocs_data[key].append(value)
                    else:
                        iocs_data[key] = [iocs_data[key], value]
                else:
                    iocs_data[key] = value
    return iocs_data, validated_count_str

def parse_phase1_5_contextual_inquiry_file(raw_text):
    initial_assessment = ""
    questions_list_strings = []
    if not raw_text: return initial_assessment, questions_list_strings
    text_to_parse = raw_text
    header_match_main = re.match(
        r"--- Contextual Inquiry Output for Alert ID: .*? ---\s*(\n--- Associated Agent ID: .*? ---\s*)?\n*",
        text_to_parse, re.DOTALL
    )
    if header_match_main: text_to_parse = text_to_parse[header_match_main.end():].strip()
    assessment_header_text = "**Initial Alert Assessment and Dimensional Focus:**"
    questions_header_text = "**Critical Investigative Questions (Guided by MITRE Technique and Provided IOCs):**"
    assessment_header_match = re.search(re.escape(assessment_header_text), text_to_parse, re.IGNORECASE)
    questions_header_match = re.search(re.escape(questions_header_text), text_to_parse, re.IGNORECASE)
    assessment_content_start = -1
    questions_content_start = -1
    if assessment_header_match:
        assessment_content_start = assessment_header_match.end()
    if questions_header_match:
        questions_content_start = questions_header_match.end()
    if assessment_content_start != -1 and questions_content_start != -1:
        if assessment_content_start < questions_header_match.start():
            initial_assessment = text_to_parse[assessment_content_start:questions_header_match.start()].strip()
            questions_block = text_to_parse[questions_content_start:].strip()
        else:
            questions_block = text_to_parse[questions_content_start:assessment_header_match.start()].strip()
            initial_assessment = text_to_parse[assessment_content_start:].strip()
    elif assessment_content_start != -1:
        initial_assessment = text_to_parse[assessment_content_start:].strip()
        questions_block = ""
    elif questions_content_start != -1:
        initial_assessment = text_to_parse[:questions_header_match.start()].strip()
        questions_block = text_to_parse[questions_content_start:].strip()
    else:
        initial_assessment = text_to_parse.strip()
        questions_block = ""
    if questions_block:
        question_item_pattern = re.compile(r"^\s*\d+[\.\)]\s*(.+)$", re.MULTILINE)
        for match in question_item_pattern.finditer(questions_block):
            question_text = match.group(1).strip()
            if question_text:
                questions_list_strings.append(question_text)
        if not questions_list_strings and questions_block.strip():
            for line in questions_block.split('\n'):
                cleaned_line = re.sub(r"^\s*\d+[\.\)]\s*", "", line.strip())
                if cleaned_line and len(cleaned_line) > 5:
                    questions_list_strings.append(cleaned_line)
    return initial_assessment.strip(), questions_list_strings

def parse_phase2_plan_file_content(raw_text):
    if not raw_text: return None, None, None, []
    alert_id_match = re.search(r"--- Detailed Investigative Plan for Alert ID: (.*?) ---", raw_text)
    alert_id = alert_id_match.group(1).strip() if alert_id_match else "N/A"
    agent_id_match = re.search(r"--- Agent ID: (.*?) ---", raw_text)
    agent_id = agent_id_match.group(1).strip() if agent_id_match else "N/A"
    initial_assessment_match = re.search(
        r"--- Initial Assessment \(from Contextual Inquiry\) ---\s*(.*?)\s*--- Validated IOCs Used for Plan Generation ---",
        raw_text, re.DOTALL
    )
    initial_assessment = initial_assessment_match.group(1).strip() if initial_assessment_match else "Assessment not parsed."
    validated_iocs_match = re.search(
        r"--- Validated IOCs Used for Plan Generation ---\s*(.*?)\s*--- Detailed Investigative Questions and Plans ---",
        raw_text, re.DOTALL
    )
    validated_iocs_text = validated_iocs_match.group(1).strip() if validated_iocs_match else "Validated IOCs not parsed."
    questions_and_plans = []
    plans_block_match = re.search(
        r"--- Detailed Investigative Questions and Plans ---\s*(.*)",
        raw_text, re.DOTALL
    )
    if plans_block_match:
        plans_content = plans_block_match.group(1).strip()
        individual_plan_pattern = re.compile(
            r"Question \d+:\s*(.*?)\s*Detailed Plan:\s*(.*?)(?=\nQuestion \d+:|\n-{50}|\Z)",
            re.DOTALL | re.IGNORECASE
        )
        for match in individual_plan_pattern.finditer(plans_content):
            question = match.group(1).strip()
            plan_text = match.group(2).strip()
            if plan_text.endswith("\n" + "-" * 50):
                plan_text = plan_text[:-len("\n" + "-" * 50)].strip()
            elif plan_text.endswith("-" * 50):
                 plan_text = plan_text[:-len("-" * 50)].strip()
            questions_and_plans.append({
                "question": question,
                "plan_text": plan_text
            })
    if not questions_and_plans and plans_block_match and plans_block_match.group(1).strip():
        note_match = re.search(r"Note: (.*)", plans_block_match.group(1).strip(), re.IGNORECASE)
        if note_match:
            questions_and_plans.append({"question": "Note", "plan_text": note_match.group(1).strip()})
        elif "No specific questions or plans were generated" in plans_block_match.group(1).strip():
             questions_and_plans.append({"question": "Status", "plan_text": plans_block_match.group(1).strip()})
    return initial_assessment, validated_iocs_text, questions_and_plans


# --- Streamlit App UI ---
st.set_page_config(layout="wide", page_title="AI SOC Multi-Phase Viewer")
st.title("🛡️ AI SOC - Multi-Phase Alert Investigation")
st.markdown(f"Data from GitHub: `{GITHUB_USERNAME}/{GITHUB_REPO_NAME}` (branch: `{GITHUB_BRANCH}`)")

# Calls to data loading functions no longer pass token
all_wazuh_alerts_map, wazuh_load_error_msg, wazuh_error_raw_content = load_wazuh_alerts_data_from_github(
    GITHUB_USERNAME, GITHUB_REPO_NAME, WAZUH_ALERTS_FILE_PATH, GITHUB_BRANCH
)

if wazuh_load_error_msg:
    st.error(f"Problem loading original Wazuh alerts data: {wazuh_load_error_msg}")
    if wazuh_error_raw_content:
        with st.expander("View Problematic Wazuh Alerts JSON Content"):
            st.text_area("Content:", wazuh_error_raw_content[:1000], height=200, key="wazuh_error_json_display")
if all_wazuh_alerts_map is not None and not wazuh_load_error_msg:
    st.success(
        f"Successfully loaded {len(all_wazuh_alerts_map)} original Wazuh alerts from '{WAZUH_ALERTS_FILE_PATH}'.")
elif all_wazuh_alerts_map is None and not wazuh_load_error_msg: # No data but also no explicit error from loading
    st.warning(f"No alerts with 'id' fields parsed from '{WAZUH_ALERTS_FILE_PATH}', or file was empty/inaccessible from public repo.")


alert_id_dirs = list_github_directories(
    GITHUB_USERNAME, GITHUB_REPO_NAME, ALERTS_DATA_BASE_PATH, GITHUB_BRANCH # No token
)

st.sidebar.header("🚨 Alert Selection")
options_for_selectbox = [""] + alert_id_dirs if alert_id_dirs else [""]
selected_alert_id = st.sidebar.selectbox(
    "Select Alert ID:", options_for_selectbox, key="main_alert_id_selector",
    format_func=lambda x: "Select an Alert" if x == "" else x
)

if not selected_alert_id:
    st.info("👈 Please select an Alert ID from the sidebar to view its phase details.")
else:
    st.header(f"Investigation for Alert ID: {selected_alert_id}")

    tab_titles = [
        "Original Alert",
        "Phase 1: IOC Extraction",
        "Phase 1.5: Contextual Inquiry",
        "Phase 2: Investigative Plans"
    ]
    tabs = st.tabs(tab_titles)

    with tabs[0]:
        st.subheader("📜 Full Original Wazuh Alert")
        original_alert_data_to_display = None
        if all_wazuh_alerts_map:
            original_alert_data_to_display = all_wazuh_alerts_map.get(selected_alert_id)
        if original_alert_data_to_display:
            st.json(original_alert_data_to_display)
        elif all_wazuh_alerts_map is not None: # Map was loaded but ID not found
            st.warning(f"Original Wazuh alert for ID '{selected_alert_id}' not found in the loaded alerts file.")
        else: # Map itself failed to load
            st.info("Original Wazuh alerts data couldn't be loaded (see messages above if any).")

    if len(tabs) > 1:
        with tabs[1]:
            st.subheader("📄 Extracted IOCs")
            p1_ioc_file_path = f"{ALERTS_DATA_BASE_PATH}/{selected_alert_id}/phase1_iocs.txt"
            p1_ioc_file_content = get_github_file_content(GITHUB_USERNAME, GITHUB_REPO_NAME, p1_ioc_file_path,
                                                          GITHUB_BRANCH) # No token
            if p1_ioc_file_content:
                parsed_iocs, validated_count = parse_phase1_ioc_file_content(p1_ioc_file_content)
                st.info(f"**Validated IOC Keys Count (from IOC file):** {validated_count}")
                if parsed_iocs:
                    df_iocs = pd.DataFrame(list(parsed_iocs.items()), columns=["IOC Type", "Value"])
                    st.table(df_iocs.set_index("IOC Type"))
                else:
                    st.warning("Could not parse IOCs from P1 file. Raw content might not contain expected IOC format.")
                with st.expander("Raw P1 IOC File Content"):
                    st.text_area(f"P1 Content:", p1_ioc_file_content, height=300, key=f"p1_raw_ioc_{selected_alert_id}")
            elif alert_id_dirs:
                st.info(f"P1 IOC file not found: '{p1_ioc_file_path}'. File might not exist or could not be loaded for this alert.")

    if len(tabs) > 2:
        with tabs[2]:
            st.subheader("🤔 Phase 1.5: Contextual Inquiry Output")
            p1_5_context_file_path = f"{ALERTS_DATA_BASE_PATH}/{selected_alert_id}/phase1.5_contextual_inquiry.txt"
            p1_5_context_file_content = get_github_file_content(
                GITHUB_USERNAME, GITHUB_REPO_NAME, p1_5_context_file_path, GITHUB_BRANCH # No token
            )
            if p1_5_context_file_content:
                initial_assessment, questions_list = parse_phase1_5_contextual_inquiry_file(p1_5_context_file_content)
                if initial_assessment:
                    st.markdown("**Initial Alert Assessment and Dimensional Focus:**")
                    st.markdown(initial_assessment)
                else:
                    st.markdown("**Initial Alert Assessment and Dimensional Focus:**")
                    st.info("No assessment information parsed from the file, or section not found.")
                st.markdown("---")
                if questions_list:
                    st.markdown("\n**Critical Investigative Questions:**")
                    for i, q_text in enumerate(questions_list):
                        st.markdown(f"{i + 1}. {q_text}")
                else:
                    st.markdown("\n**Critical Investigative Questions:**")
                    st.info("No questions parsed from the file, or questions section not found.")
                with st.expander("Raw Phase 1.5 Contextual Inquiry File Content"):
                    st.text_area(f"P1.5 Content:", p1_5_context_file_content, height=400,
                                 key=f"p1_5_raw_context_{selected_alert_id}")
            elif alert_id_dirs:
                st.info(f"Phase 1.5 Contextual Inquiry file not found: '{p1_5_context_file_path}'. File might not exist or could not be loaded for this alert.")

    if len(tabs) > 3:
        with tabs[3]:
            st.subheader("📝 Generated Investigative Plans")
            p2_plans_file_path = f"{ALERTS_DATA_BASE_PATH}/{selected_alert_id}/phase2_detailed_investigation_plans.txt"
            p2_plans_file_content = get_github_file_content(
                GITHUB_USERNAME, GITHUB_REPO_NAME, p2_plans_file_path, GITHUB_BRANCH # No token
            )
            if p2_plans_file_content:
                phase2_assessment, phase2_iocs, phase2_q_and_plans = parse_phase2_plan_file_content(
                    p2_plans_file_content)
                if phase2_assessment and phase2_assessment != "Assessment not parsed.":
                    st.markdown("**Recap: Initial Alert Assessment (from Contextual Inquiry):**")
                    st.markdown(phase2_assessment)
                else:
                    st.info("Initial assessment section not found or parsed from Phase 2 file.")
                st.markdown("---")
                if phase2_iocs and phase2_iocs != "Validated IOCs not parsed.":
                    st.markdown("**Recap: Validated IOCs Used for Plan Generation:**")
                    try:
                        iocs_json = json.loads(phase2_iocs)
                        st.json(iocs_json)
                    except json.JSONDecodeError:
                        st.text_area("IOCs Text:", value=phase2_iocs, height=150, disabled=True, key=f"p2_iocs_{selected_alert_id}")
                else:
                    st.info("Validated IOCs section not found or parsed from Phase 2 file.")
                st.markdown("---")
                if phase2_q_and_plans:
                    st.markdown("**Detailed Investigative Questions and Plans:**")
                    for i, plan_data in enumerate(phase2_q_and_plans):
                        with st.container():
                            st.markdown(f"##### Question {i+1}: {plan_data.get('question', 'N/A')}")
                            st.markdown("###### Detailed Plan:")
                            st.markdown(plan_data.get('plan_text', "No plan details parsed."))
                            if i < len(phase2_q_and_plans) - 1:
                                st.markdown("---")
                else:
                    st.info("No individual plans were parsed from the Phase 2 file. The 'Detailed Investigative Questions and Plans' section might be empty, malformed, or only contain a note.")
                with st.expander("Raw Phase 2 Plans File Content"):
                    st.text_area(f"P2 Content:", p2_plans_file_content, height=400,
                                 key=f"p2_raw_plans_{selected_alert_id}")
            elif alert_id_dirs:
                st.info(f"Phase 2 plans file not found: '{p2_plans_file_path}'. File might not exist or could not be loaded for this alert.")

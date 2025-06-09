# streamlit_app.py

import streamlit as st
import requests
import base64
import json
import re

# --- Page Configuration (MUST BE THE FIRST STREAMLIT COMMAND) ---
st.set_page_config(layout="wide", page_title="AI SOC Dashboard")

# --- GitHub Configuration ---
GITHUB_USERNAME = "abhinmodgil"
GITHUB_REPO_NAME = "aisoc_output"
GITHUB_BRANCH = "main"


# --- GitHub Helper Functions (Public Repo Version - No Token Needed) ---

@st.cache_data(ttl=300)  # Cache the list of alerts for 5 minutes
def list_alert_directories(username, repo, branch):
    """
    Lists directories (alert IDs) from the root of a PUBLIC GitHub repository.
    Filters for directories that look like alert IDs.
    """
    api_url = f"https://api.github.com/repos/{username}/{repo}/contents/?ref={branch}"
    dir_names = []
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        for item in response.json():
            # Filter for directories whose names are numeric (allowing one decimal point)
            if item["type"] == "dir" and item["name"].replace('.', '', 1).isdigit():
                dir_names.append(item["name"])
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            st.error(f"The repository '{repo}' was not found. Please check that it is public and the name is correct.")
        elif e.response.status_code == 403:
            st.error("API rate limit exceeded for unauthenticated requests. Please wait a while before reloading.")
        else:
            st.error(f"HTTP error listing alert directories: {e}")
    except Exception as e:
        st.error(f"An unexpected error occurred while listing directories: {e}")
    return sorted(dir_names, reverse=True)


@st.cache_data(ttl=300) # Cache file content for 5 minutes
def get_github_file_content(username, repo, file_path, branch):
    """Fetches and decodes file content from a PUBLIC GitHub file path."""
    api_url = f"https://api.github.com/repos/{username}/{repo}/contents/{file_path}?ref={branch}"
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        content_data = response.json()
        if "content" in content_data:
            return base64.b64decode(content_data["content"]).decode('utf-8')
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 404:
            st.warning(f"Could not retrieve file '{file_path}': HTTP {e.response.status_code}")
    except Exception as e:
        st.error(f"Error getting file content for '{file_path}': {e}")
    return None

# --- Main App UI ---

st.title("🛡️ AI SOC Investigation Dashboard")
st.info(f"Displaying investigation results from public GitHub repository: `{GITHUB_USERNAME}/{GITHUB_REPO_NAME}`")

alert_ids = list_alert_directories(GITHUB_USERNAME, GITHUB_REPO_NAME, GITHUB_BRANCH)

st.sidebar.header("🚨 Alert Selection")
selected_alert_id = st.sidebar.selectbox(
    "Select an Alert ID to Review:",
    options=[""] + alert_ids,
    format_func=lambda x: "Select an Alert..." if not x else x
)

if not selected_alert_id:
    st.info("👈 Please select an Alert ID from the sidebar to view its complete investigation.")
    st.markdown("---")
    st.subheader("Welcome to the AI SOC Dashboard")
    st.markdown("This dashboard provides a detailed, multi-phase analysis of security alerts processed by the AI SOC. Once you select an alert, you will see:")
    st.markdown("""
    - **A Final Verdict and Risk Score:** For at-a-glance triage.
    - **An Executive Summary:** A human-readable narrative of the investigation.
    - **Recommended Actions:** Concrete next steps for an analyst.
    - **Deep-Dive Tabs:** Access to the raw data and AI reasoning from every phase of the pipeline.
    """)
else:
    # --- Data Fetching for the Selected Alert ---
    st.header(f"Investigation Report: {selected_alert_id}")
    
    filenames = {
        "iocs": "1_iocs.json", "prio": "2_prioritization.json", "questions": "3_questions.md",
        "plan": "4_execution_plan.md", "results": "5_tool_results.json", "scores": "6_dimension_scores.json",
        "risk": "7_risk_score.json", "summary": "8_final_summary.md"
    }
    
    data = {}
    with st.spinner(f"Fetching investigation data for {selected_alert_id}..."):
        for key, fname in filenames.items():
            data[key] = get_github_file_content(GITHUB_USERNAME, GITHUB_REPO_NAME, f"{selected_alert_id}/{fname}", GITHUB_BRANCH)

    # --- Primary Dashboard View ---
    summary_md = data["summary"]
    risk_json_str = data["risk"]
    
    if summary_md and risk_json_str:
        try:
            risk_data = json.loads(risk_json_str)
            risk_score = risk_data.get("final_risk_score", 0)

            verdict_search = re.search(r"### Final Verdict\s*\n\s*\*\*(.*?)\*\*", summary_md, re.IGNORECASE)
            if not verdict_search:
                 verdict_search = re.search(r"### Final Verdict\s*\n(.*?)\s*\n", summary_md, re.IGNORECASE)

            verdict = verdict_search.group(1).strip() if verdict_search else "N/A"
            verdict_color = {"malicious": "red", "suspicious": "orange", "benign": "green"}.get(verdict.lower(), "grey")

            col1, col2 = st.columns([1, 4])
            with col1:
                st.metric(label="Final Risk Score", value=f"{risk_score} / 100")
            with col2:
                st.markdown(f"### Final Verdict: <span style='color:{verdict_color}; font-weight:bold;'>{verdict}</span>", unsafe_allow_html=True)
            
            st.markdown("---")
            st.markdown(summary_md, unsafe_allow_html=True)

        except (json.JSONDecodeError, AttributeError, IndexError) as e:
            st.error(f"Could not render the summary dashboard. Error: {e}")
            st.markdown("##### Raw Summary File Content:"); st.text(summary_md or "File not found.")
            st.markdown("##### Raw Risk Score File Content:"); st.text(risk_json_str or "File not found.")
    else:
        st.warning("The Final Summary (8_final_summary.md) or Risk Score (7_risk_score.json) file was not found. The investigation may be incomplete.")

    # --- Deep Dive Tabs ---
    st.markdown("---")
    st.subheader("Investigation Phase Deep Dive")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Evidence & Scoring", "Tool Execution", "AI Planning", "Initial Analysis"])

    with tab1:
        st.markdown("#### Phase 7: Risk Score Breakdown")
        if data["risk"]: st.json(data["risk"])
        else: st.info("File not found: `7_risk_score.json`")
        st.markdown("#### Phase 6: Dimension Scores")
        if data["scores"]: st.json(data["scores"])
        else: st.info("File not found: `6_dimension_scores.json`")

    with tab2:
        st.markdown("#### Phase 5: Tool Execution Results")
        if data["results"]:
            try:
                results_list = json.loads(data["results"])
                for i, result_item in enumerate(results_list):
                    cmd = result_item.get("command", {})
                    with st.expander(f"**Step {i+1}: {cmd.get('tool', 'N/A')}** - {cmd.get('question', 'N/A')}"):
                        st.markdown("**Query/Action:**"); st.code(cmd.get('query', 'N/A'), language='sql')
                        st.markdown("**Result:**"); st.text(result_item.get('result', 'N/A'))
            except json.JSONDecodeError:
                st.error("Could not parse `5_tool_results.json`."); st.text(data["results"])
        else:
            st.info("File not found: `5_tool_results.json`")

    with tab3:
        st.markdown("#### Phase 4: AI Execution Plan")
        if data["plan"]: st.markdown(data["plan"], unsafe_allow_html=True)
        else: st.info("File not found: `4_execution_plan.md`")
        st.markdown("#### Phase 3: AI Investigative Questions")
        if data["questions"]: st.markdown(data["questions"], unsafe_allow_html=True)
        else: st.info("File not found: `3_questions.md`")

    with tab4:
        st.markdown("#### Phase 2: Investigation Prioritization")
        if data["prio"]: st.json(data["prio"])
        else: st.info("File not found: `2_prioritization.json`")
        st.markdown("#### Phase 1: Extracted IOCs")
        if data["iocs"]: st.json(data["iocs"])
        else: st.info("File not found: `1_iocs.json`")

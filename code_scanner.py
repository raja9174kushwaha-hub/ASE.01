import streamlit as st
import re
import time
from typing import List, Dict

# Simple regex-based patterns for demonstration SAST
SAST_PATTERNS = {
    "python": [
        (r"eval\s*\(", "Critical", "Avoid using eval(), it allows arbitrary code execution."),
        (r"subprocess\.call\s*\(.*shell\s*=\s*True", "High", "Shell=True can lead to command injection."),
        (r"debug\s*=\s*True", "Medium", "Ensure debug mode is disabled in production."),
        (r"password\s*=\s*['\"].+['\"]", "High", "Hardcoded password detected."),
        (r"api_key\s*=\s*['\"].+['\"]", "High", "Hardcoded API key detected."),
    ],
    "javascript": [
        (r"eval\s*\(", "Critical", "Avoid using eval()."),
        (r"document\.write\s*\(", "Medium", "document.write can be unsafe."),
        (r"innerHTML", "Medium", "innerHTML usage might lead to XSS if input is not sanitized."),
    ],
    "general": [
        (r"AKIA[0-9A-Z]{16}", "Critical", "AWS Access Key ID detected."),
        (r"(?i)private_key", "High", "Potential private key file or variable."),
    ]
}

def analyze_code(content: str, filename: str) -> List[Dict]:
    findings = []
    
    # Check general patterns
    for pattern, severity, desc in SAST_PATTERNS["general"]:
        if re.search(pattern, content):
            findings.append({"file": filename, "severity": severity, "issue": desc, "line": "N/A"})

    # Check language specific
    if filename.endswith(".py"):
        for pattern, severity, desc in SAST_PATTERNS["python"]:
            matches = re.finditer(pattern, content)
            for m in matches:
                # Find line number roughly
                line_no = content[:m.start()].count('\n') + 1
                findings.append({"file": filename, "severity": severity, "issue": desc, "line": line_no})
    
    elif filename.endswith(".js"):
        for pattern, severity, desc in SAST_PATTERNS["javascript"]:
            matches = re.finditer(pattern, content)
            for m in matches:
                line_no = content[:m.start()].count('\n') + 1
                findings.append({"file": filename, "severity": severity, "issue": desc, "line": line_no})

    return findings

def run_code_scanner_view():
    st.header("📜 Code Security Inspector (SAST)")
    st.markdown("Automated static analysis for identifying security flaws and hardcoded secrets in source code.")

    with st.container():
        st.subheader("📁 Source Code Ingestion")
        uploaded_files = st.file_uploader("Drop source files here (Python, JavaScript, Text)", accept_multiple_files=True, type=['py', 'js', 'txt', 'java', 'go'])
    
    if uploaded_files:
        if st.button("🚀 Analyze Source Code", use_container_width=True):
            with st.status("🔍 Analyzing Syntax Trees...", expanded=True) as status:
                st.write("📂 Reading file contents...")
                all_findings = []
                files_scanned = 0
                
                for u_file in uploaded_files:
                    try:
                        content = u_file.read().decode("utf-8")
                        findings = analyze_code(content, u_file.name)
                        all_findings.extend(findings)
                        files_scanned += 1
                        st.write(f"✅ Scanned {u_file.name}")
                    except Exception as e:
                        st.error(f"❌ Failed to read {u_file.name}: {e}")
                
                time.sleep(0.5)
                status.update(label="Scanning Complete", state="complete", expanded=False)

            total_vulns = len(all_findings)
            critical_count = len([f for f in all_findings if f['severity'] == 'Critical'])
            
            st.markdown("### 📊 Scan Summary")
            m1, m2, m3 = st.columns(3)
            m1.metric("Files Scanned", files_scanned)
            m2.metric("Issues Detected", total_vulns, delta_color="inverse")
            m3.metric("Critical Flaws", critical_count, delta_color="inverse")
            
            st.markdown("---")
            
            if total_vulns == 0:
                st.success("✅ **Clean Base:** No obvious security vulnerabilities found in the uploaded files.")
                st.balloons()
            else:
                st.error(f"🚨 **Security Alert:** Found {total_vulns} potential vulnerabilities!")
                st.subheader("📝 Detailed Findings")
                
                for i, f in enumerate(all_findings):
                    severity = f['severity']
                    color = "#ff4b4b" if severity == "Critical" else ("#ffa500" if severity == "High" else "#00ffcc")
                    icon = "🔥" if severity == "Critical" else "⚠️"
                    
                    with st.container():
                         col_icon, col_details = st.columns([1, 20])
                         with col_icon:
                             st.markdown(f"## {icon}")
                         with col_details:
                             st.markdown(f"**{f['file']}** (Line {f['line']}) — <span style='color:{color}'>**[{severity}]**</span>", unsafe_allow_html=True)
                             st.markdown(f"{f['issue']}")
                             st.code(f"# Snippet from {f['file']}\n...", language="python") # Placeholder for context
                    st.markdown("---")

if __name__ == "__main__":
    run_code_scanner_view()

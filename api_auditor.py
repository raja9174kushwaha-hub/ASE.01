import streamlit as st
import time
import random
from typing import List, Dict

def run_api_auditor_view():
    st.header("🔌 API Security Auditor")
    st.markdown("Automated security testing for REST & GraphQL endpoints focusing on OWASP API Top 10.")

    with st.container():
        col_in, col_set = st.columns([2, 1])
        with col_in:
            api_url = st.text_input("Target API Endpoint", placeholder="https://api.example.com/v1")
        with col_set:
            st.selectbox("Scan Profile", ["OWASP API Top 10", "Business Logic Fuzzing", "Legacy API Scan"])
    
    with st.expander("🛠️ Authentication & Headers Configuration"):
        c1, c2 = st.columns(2)
        with c1:
            st.multiselect("Active Checks", 
                          ["BOLA (ID Insecure Reference)", "Broken Auth", "Data Exposure", "Mass Assignment"],
                          default=["BOLA (ID Insecure Reference)", "Broken Auth"])
        with c2:
            st.text_area("Request Headers (JSON)", value='{"Authorization": "Bearer <TOKEN>", "Content-Type": "application/json"}', height=100)

    if st.button("🚀 Initiating API Fuzzing", use_container_width=True):
        if not api_url:
            st.warning("Please define a target API URL.")
            return

        with st.status("📡 Fuzzing API Endpoints...", expanded=True) as status:
            st.write("🔍 Discovering API schema (Swagger/OpenAPI)...")
            time.sleep(0.5)
            st.write("💉 Injecting malformed payloads...")
            time.sleep(0.5)
            st.write("🔑 Testing authorization boundaries (BOLA)...")
            time.sleep(0.5)
            status.update(label="Audit Session Completed", state="complete", expanded=False)

        # Simulation Logic
        results = [
            {"id": "API-01", "name": "Broken Object Level Auth (BOLA)", "endpoint": "/users/{id}", "status": "Vulnerable", "severity": "Critical"},
            {"id": "API-02", "name": "Excessive Data Exposure", "endpoint": "/admin/config", "status": "Vulnerable", "severity": "High"}
        ]
        
        # Metrics
        st.markdown("### 📊 Audit Telemetry")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Endpoints Scanned", "42", delta_color="off")
        m2.metric("Payloads Sent", "1,337", delta_color="off")
        m3.metric("Avg Latency", "145ms", "-12ms", delta_color="normal")
        m4.metric("Vulns Found", len(results), "Critical", delta_color="inverse")
        
        st.markdown("---")

        if results:
            st.markdown("### 🚨 Vulnerability Report")
            for res in results:
                severity = res['severity']
                color = "#ff4b4b" if severity == "Critical" else "#ffa500"
                
                with st.container():
                    c_icon, c_info = st.columns([1, 15])
                    with c_icon:
                        st.markdown(f"## {'🔥' if severity == 'Critical' else '⚠️'}")
                    with c_info:
                        st.markdown(f"**{res['name']}** on `{res['endpoint']}`")
                        st.markdown(f"Severity: <span style='color:{color}'>**{severity}**</span>", unsafe_allow_html=True)
                        with st.expander(f"🛠️ View Remediation for {res['id']}"):
                            st.info("**Recommendation:** Implement strict resource ownership checks in the controller logic.")
                            st.code("def get_user(id):\n  if current_user.id != id:\n    raise Forbidden()\n  return db.get(id)", language="python")

        else:
            st.balloons()
            st.success("✅ API appears robust against scanned vectors.")

if __name__ == "__main__":
    run_api_auditor_view()

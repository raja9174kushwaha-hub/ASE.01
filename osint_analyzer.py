import streamlit as st
import socket
import requests
import time

def get_dns_records(domain):
    records = []
    # A Record
    try:
        ip = socket.gethostbyname(domain)
        records.append({"Type": "A", "Value": ip})
    except:
        pass
    
    # MX Record (Simulation via socket not easy without dnspython, skipping to avoid complexity or external deps)
    # We will stick to basic A-record for "Real" proof.
    
    return records

def get_tech_stack(domain):
    stack = []
    try:
        url = f"http://{domain}"
        resp = requests.head(url, timeout=3)
        headers = resp.headers
        
        if "Server" in headers:
            stack.append(f"Server: {headers['Server']}")
        if "X-Powered-By" in headers:
            stack.append(f"Powered By: {headers['X-Powered-By']}")
        if "X-AspNet-Version" in headers:
            stack.append(f"ASP.NET: {headers['X-AspNet-Version']}")
            
        return stack, headers
    except:
        return [], {}

def run_osint_view():
    st.header("🔍 OSINT Reconnaissance (Active)")
    st.markdown("Real-time intelligence gathering using standard DNS and HTTP probes.")

    with st.container():
        st.subheader("🎯 Target Definition")
        domain = st.text_input("Root Target Domain", placeholder="example.com")
        
    if st.button("🚀 Execute Reconnaissance", use_container_width=True):
        if not domain:
            st.error("Please define a root domain.")
            return

        with st.status("📡 Probing Target...", expanded=True) as status:
            st.write(f"🌐 Resolving root domain `{domain}`...")
            
            # Real DNS
            dns_records = get_dns_records(domain)
            
            # Real HTTP
            st.write("🛡️ Analyzing HTTP headers...")
            tech_stack, raw_headers = get_tech_stack(domain)
            
            status.update(label="Reconnaissance Complete", state="complete", expanded=False)

        # Display Results
        st.markdown("### 🗺️ Surface Map")
        m1, m2 = st.columns(2)
        m1.metric("DNS Entries", len(dns_records), delta_color="off")
        m2.metric("Tech Signatures", len(tech_stack), delta_color="off")
        
        st.markdown("---")
        
        res_col1, res_col2 = st.columns(2)
        
        with res_col1:
            st.subheader("Infrastructure (DNS)")
            if dns_records:
                for rec in dns_records:
                    st.write(f"**{rec['Type']}:** `{rec['Value']}`")
            else:
                st.info("No DNS A-Records found or resolution failed.")
        
        with res_col2:
            st.subheader("Technology (HTTP Headers)")
            if tech_stack:
                for t in tech_stack:
                    st.code(t, language=None)
            else:
                st.info("No technology signatures exposed in headers.")
                
        if raw_headers:
            with st.expander("View Raw HTTP Headers"):
                st.json(dict(raw_headers))

if __name__ == "__main__":
    run_osint_view()

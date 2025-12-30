import streamlit as st
import pandas as pd
import subprocess
import re

def get_real_network_activity():
    """
    Executes 'netstat -ano' to get REAL active connections.
    Returns a DataFrame.
    """
    try:
        # Run netstat (Windows)
        # -a: Displays all active connections and the TCP and UDP ports on which the computer is listening.
        # -n: Displays active TCP connections, however, addresses and port numbers are expressed numerically
        # -o: Displays the owning process ID associated with each connection.
        cmd = ["netstat", "-ano"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        lines = result.stdout.splitlines()
        data = []
        for line in lines:
            # Parse lines like: "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       984"
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 5 and parts[0] in ["TCP", "UDP"]:
                data.append({
                    "Protocol": parts[0],
                    "Local Address": parts[1],
                    "Foreign Address": parts[2],
                    "State": parts[3] if parts[0] == "TCP" else "N/A",
                    "PID": parts[-1]
                })
        
        return pd.DataFrame(data)
    except Exception as e:
        return pd.DataFrame({"Error": [str(e)]})

def run_topology_view():
    st.header("🛡️ Host Defensive Monitor")
    st.markdown("Real-time view of active network connections and listening ports on this host.")

    if st.button("🔄 Refresh Network Table"):
        st.cache_data.clear()

    df = get_real_network_activity()

    if not df.empty and "Protocol" in df.columns:
        
        # Summary Metrics
        total_conns = len(df)
        listening = len(df[df['State'] == 'LISTENING'])
        established = len(df[df['State'] == 'ESTABLISHED'])
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Connections", total_conns)
        c2.metric("Listening Ports", listening)
        c3.metric("Established Links", established)
        
        st.subheader("📡 Active Connections Table")
        
        # Filter options
        filter_state = st.multiselect("Filter State", df["State"].unique(), default=["LISTENING", "ESTABLISHED"])
        if filter_state:
            df_show = df[df["State"].isin(filter_state)]
        else:
            df_show = df
            
        st.dataframe(df_show, use_container_width=True, hide_index=True)
        
        if established > 0:
            st.info(f"ℹ️ {established} established connections detected. Review 'Foreign Address' for suspicious outgoing traffic.")
            
    else:
        st.error("Failed to retrieve network statistics. Ensure specific permissions are granted.")

def run_honeypot_view():
    st.header("🍯 Honeypot Stub (Inactive)")
    st.warning("⚠️ The simulated honeypot feature has been disabled to ensure 0% fake data. Real honeypot functionality requires deploying external sensors.")
    st.info("Please use the 'Host Defensive Monitor' above for real network data.")

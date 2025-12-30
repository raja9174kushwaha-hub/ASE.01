import streamlit as st
import requests
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

def attempt_login(url, username, password, method="POST"):
    """
    Attempts a real login request.
    Returns result dict: {password, status, length, success}
    """
    try:
        data = {"username": username, "password": password, "email": username}
        
        start_time = time.time()
        if method == "POST":
            # Real request
            resp = requests.post(url, data=data, timeout=5, allow_redirects=False)
        else:
            resp = requests.get(url, auth=(username, password), timeout=5)
        
        duration = time.time() - start_time
        
        return {
            "password": password,
            "status": resp.status_code,
            "length": len(resp.text),
            "duration": duration, # kept as float for sorting/formatting
            "error": None
        }
    except Exception as e:
        return {"password": password, "status": 0, "length": 0, "duration": 0.0, "error": str(e)}

def run_brute_force_view():
    st.header("🔑 Auth Weakness Tester (Active)")
    st.markdown("""
    **REAL Mode**: This module actively attempts to log in to the target using the provided dictionary.
    **Warning**: Only use on systems you own or have permission to test.
    """)

    with st.container():
        st.subheader("🎯 Configuration")
        col1, col2 = st.columns(2)
        with col1:
            target_url = st.text_input("Target Login Endpoint", placeholder="http://localhost:8000/token")
            username = st.text_input("Target Username", value="admin@example.com")
            
        with col2:
            default_passwords = "password\n123456\nadmin\nwelcome\nqwerty"
            pass_list_str = st.text_area("Password List (One per line)", value=default_passwords, height=150)
    
    if st.button("🚀 Start Active Test", use_container_width=True):
        if not target_url:
            st.error("Please define a target endpoint.")
            return

        passwords = [p.strip() for p in pass_list_str.split('\n') if p.strip()]
        
        st.write(f"Testing **{len(passwords)}** passwords against `{username}` at `{target_url}`...")
        
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Real Execution Loop
        for i, pwd in enumerate(passwords):
            status_text.text(f"Testing password: {pwd}...")
            res = attempt_login(target_url, username, pwd)
            results.append(res)
            progress_bar.progress((i + 1) / len(passwords))
            time.sleep(0.1) # Politeness delay
            
        status_text.empty()
        st.success("Test Complete.")
        
        st.subheader("Results Analysis")
        
        # Display as a real data table with config
        if results:
            df = pd.DataFrame(results)
            
            st.dataframe(
                df,
                use_container_width=True,
                column_config={
                    "password": "Password Attempt",
                    "status": st.column_config.NumberColumn(
                        "Status Code",
                        help="HTTP Response Code (200=OK, 401=Unauth)",
                        format="%d"
                    ),
                    "length": st.column_config.ProgressColumn(
                        "Response Size",
                        help="Length of response body (chars)",
                        format="%d bytes",
                        min_value=0,
                        max_value=df['length'].max(),
                    ),
                    "duration": st.column_config.NumberColumn(
                        "Time (s)",
                        format="%.2f",
                    ),
                    "error": "Errors"
                },
                hide_index=True
            )
        
        st.info("💡 **Tip:** Look for 'Status Code' 200 or significantly different 'Response Size' values to identify valid credentials.")

if __name__ == "__main__":
    run_brute_force_view()

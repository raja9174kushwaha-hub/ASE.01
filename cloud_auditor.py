import streamlit as st
import time

def run_cloud_auditor_view():
    st.header("🐳 Docker & Cloud Auditor")
    st.markdown("Audits container configurations and cloud surface area for misconfigurations.")

    tab1, tab2 = st.tabs(["🐳 Docker Audit", "☁️ Cloud Config"])

    with tab1:
        st.subheader("Dockerfile Security Audit")
        docker_content = st.text_area("Paste Dockerfile content", height=200, placeholder="FROM ubuntu:latest\nRUN apt-get update...")
        
        if st.button("🔍 Audit Dockerfile"):
            if "USER root" in docker_content or "FROM" in docker_content and "latest" in docker_content:
                st.error("🚩 Vulnerabilities Found!")
                st.write("- **Critical:** Running as 'root' detected.")
                st.write("- **Warning:** Using 'latest' tag instead of specific version.")
            else:
                st.success("Dockerfile looks secure based on heuristic checks!")

    with tab2:
        st.subheader("Cloud Metadata Analyzer")
        cloud_provider = st.selectbox("Select Provider", ["AWS", "Azure", "GCP"])
        st.text_input(f"{cloud_provider} IAM Role / Bucket Name")
        
        if st.button(f"📡 Scan {cloud_provider} Surface"):
            with st.spinner("Querying cloud metadata..."):
                time.sleep(2)
                st.info("Simulation: Found 3 S3 buckets with 'Public Read' access enabled.")
                st.markdown("### 🚨 Recommendation")
                st.code("Apply 'Block Public Access' (BPA) at the account level.")

if __name__ == "__main__":
    run_cloud_auditor_view()

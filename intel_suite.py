import streamlit as st
import time

def run_dark_web_view():
    st.header("🕸️ Dark Web Intelligence (Reference)")
    st.markdown("Use verified external databases to check for credential leaks and brand mentions.")

    target = st.text_input("Target Identity (Email/Domain)", placeholder="example.com")
    
    if st.button("🔎 Search External Databases", use_container_width=True):
        if not target:
            st.warning("Enter a target keyword.")
            return

        st.info(f"Initiating search context for: **{target}**")
        
        st.markdown("### 🔗 Verified Breach Databases")
        st.markdown("The following services maintain real, updated indexes of dark web leaks. **ASE does not scrape Tor locally** to ensure legal compliance and avoid false positives.")
        
        c1, c2 = st.columns(2)
        
        with c1:
            st.markdown(f"#### 1. Have I Been Pwned")
            st.markdown(f"Check if **{target}** has been compromised in known data breaches.")
            st.markdown(f"[➡️ Search HIBP](https://haveibeenpwned.com/account/{target})", unsafe_allow_html=True)
            
            st.markdown(f"#### 2. DeHashed")
            st.markdown("Search for hashed passwords and database entries.")
            st.markdown(f"[➡️ Search DeHashed](https://www.dehashed.com/search?query={target})", unsafe_allow_html=True)
            
        with c2:
            st.markdown(f"#### 3. IntelligenceX")
            st.markdown("Search Archives, Pastebins, and Darknet data.")
            st.markdown(f"[➡️ Search IntelX](https://intelx.io/?s={target})", unsafe_allow_html=True)
            
            st.markdown(f"#### 4. GreyNoise")
            st.markdown("Check if an IP is scanning the internet.")
            st.markdown(f"[➡️ Search GreyNoise](https://viz.greynoise.io/query?gnql={target})", unsafe_allow_html=True)

        st.warning("⚠️ **Note:** Real dark web scraping requires specialized access and legal authorization. Use the links above for verified intelligence.")

def run_phishing_lab_view():
    st.header("📧 AI Phishing Lab (Template Generator)")
    st.markdown("Generate security awareness templates to train your team against social engineering. **(Educational Use Only)**")

    scenario = st.selectbox("Scenario", [
        "Urgent IT Update", 
        "Unusual Login Activity", 
        "Payroll Adjustment", 
        "New Invoice", 
        "Password Expiry Notice",
        "Shared Document Request",
        "CEO Gift Card Request"
    ])
    tone = st.radio("Tone", ["Professional", "Urgent", "Friendly"], horizontal=True)
    target_name = st.text_input("Target Name (Optional)", placeholder="John Doe")

    if st.button("🤖 Generate Template", use_container_width=True):
        with st.spinner("Drafting template..."):
            time.sleep(0.5)
            
            name = target_name if target_name else "Team Member"
            
            templates = {
                "Urgent IT Update": f"SUBJECT: [URGENT] Mandatory Security Update for your workstation\n\nDear {name},\n\nOur systems indicate your machine is running an outdated security patch. Please click here (http://portal.office-update.com) to initiate the update within 24 hours to avoid service disruption.\n\nRegards,\nIT Department",
                "Unusual Login Activity": f"SUBJECT: Alert: Unusual Login Attempt detected from Unknown Location\n\nHello {name},\n\nSomeone just tried to log in to your account. If this wasn't you, please secure your account immediately.\n\nSecurity Team",
                "Payroll Adjustment": f"SUBJECT: [Action Required] Update Your Direct Deposit Information\n\nHi {name},\n\nDue to a system migration, please update your direct deposit details by EOD today.\n\nHR Department",
                "Password Expiry Notice": f"SUBJECT: Your Password Expires in 24 Hours\n\nDear {name},\n\nYour network password is set to expire tomorrow. Login to the portal to reset it now and avoid losing access.\n\nIT Support",
                "Shared Document Request": f"SUBJECT: [Confidential] Document Shared with You\n\nHi {name},\n\nA private document has been shared with you via CloudDrive.\n\nClick to view.",
                "CEO Gift Card Request": f"SUBJECT: Quick Favor Needed - {name}\n\nHey,\n\nI'm in a meeting and need you to purchase client appreciation gift cards. Please reply ASAP.\n\nThanks,\nCEO",
            }
            
            template = templates.get(scenario, "Template generation failed.")
            
            # Apply tone modifier
            if tone == "Urgent":
                template = template.replace("Dear", "URGENT:\nDear").replace("please", "IMMEDIATELY")
            elif tone == "Friendly":
                template = template.replace("Dear", "Hey").replace("Regards", "Cheers")
            
            st.markdown("### 📧 Generated Phishing Lure")
            st.code(template, language="text")
            
            st.markdown("### 🛡️ Training Indicators")
            st.write("- ⚠️ Generic greeting or mismatched names")
            st.write("- ⚠️ Urgency language ('immediately', '24 hours')")
            st.write("- ⚠️ Suspicious context (CEO asking for gift cards)")
            
            st.success("Template generated! Use this for authorized security awareness testing only.")

if __name__ == "__main__":
    run_dark_web_view()

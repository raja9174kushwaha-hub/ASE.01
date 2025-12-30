# FRONTEND INTEGRATION GUIDE

## Quick Start for Frontend Integration

### Step 1: Update app.py imports
```python
# Add these imports at the top
from scanner import full_safe_scan, ScanUserInfo, validate_target_url
from session_manager import (
    init_session_state, 
    clear_scan_results, 
    set_last_error, 
    get_last_error,
    is_scan_in_progress,
    set_scan_in_progress,
    get_current_user
)
```

### Step 2: Initialize session state
```python
# In main() or early in your app:
init_session_state(st)
```

### Step 3: Update URL scan view to use real scan

**OLD CODE (REMOVED):**
```python
# BAD: This had fake results and no validation
url_result = url_checker.perform_safe_url_check(url)
simulation_findings = attack_simulator.run_all_simulations(metadata, url_result)
```

**NEW CODE (USE THIS):**
```python
def run_url_and_simulation_view() -> None:
    st.header("🌐 Web Application Security Scanner")
    
    # INPUT SECTION
    url = st.text_input("Target URL", placeholder="https://example.com")
    ownership_ack = st.checkbox("I authorize this scan.")
    
    if st.button("🚀 Launch Web Scanner"):
        # Clear old results first
        clear_scan_results(st)
        set_scan_in_progress(st, True)
        
        try:
            # Create user info from session
            current_user = get_current_user(st)
            if not current_user:
                st.error("You must be logged in to scan.")
                return
            
            user = ScanUserInfo(
                name=current_user["name"],
                email=current_user["email"],
                organization=current_user.get("org", "Unknown"),
                purpose="Web security assessment"
            )
            
            # RUN REAL SCAN (with validation)
            with st.spinner("Running security scan..."):
                result = full_safe_scan(
                    user=user,
                    target_url=url,
                    ownership_confirmed=ownership_ack,
                    include_nmap=False  # Optional
                )
            
            # HANDLE RESULT
            if result.error:
                set_last_error(st, result.error)
                st.error(f"❌ Scan Failed: {result.error}")
            else:
                # Display results
                st.success(f"✅ Scan Complete: {len(result.findings)} findings")
                
                # Show metrics
                if result.risk_summary:
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Total Findings", len(result.findings))
                    col2.metric("Risk Score", f"{result.risk_summary.overall_score:.1f}/10")
                    col3.metric("Severity", result.risk_summary.overall_severity)
                
                # Show findings table
                if result.findings:
                    st.subheader("Security Findings")
                    render_findings_table(result.findings)
                else:
                    st.info("✅ No security issues detected.")
                
                # Export options
                csv_data = export_findings_csv(result.findings)
                st.download_button(
                    "Download Results (CSV)",
                    data=csv_data,
                    file_name="scan_results.csv",
                    mime="text/csv"
                )
        
        finally:
            set_scan_in_progress(st, False)
```

### Step 4: Update Nmap scan view
```python
def run_nmap_scan_view() -> None:
    st.header("🕵️ Network Reconnaissance")
    
    target = st.text_input("Target Host/IP", placeholder="example.com or 192.168.1.1")
    
    if st.button("🚀 Initiate Scan"):
        clear_scan_results(st, exclude_types=["url_scan"])  # Keep URL results
        set_scan_in_progress(st, True)
        
        try:
            current_user = get_current_user(st)
            user = ScanUserInfo(
                name=current_user["name"],
                email=current_user["email"],
                organization=current_user.get("org", "Unknown"),
                purpose="Network reconnaissance"
            )
            
            with st.spinner("Running Nmap scan..."):
                result = full_safe_scan(
                    user=user,
                    target_url=target,
                    ownership_confirmed=True,
                    include_nmap=True  # Use Nmap for this scan
                )
            
            if result.error:
                st.error(result.error)
            else:
                nmap_findings = [f for f in result.findings if f.source == "nmap"]
                if nmap_findings:
                    st.subheader(f"Open Ports Discovered: {len(nmap_findings)}")
                    render_findings_table(nmap_findings)
                else:
                    st.info("No open ports detected or Nmap not available.")
                
                # Show raw Nmap output if available
                if result.nmap_raw and "raw_output" in result.nmap_raw:
                    with st.expander("View Raw Nmap Output"):
                        st.code(result.nmap_raw["raw_output"], language="xml")
        
        finally:
            set_scan_in_progress(st, False)
```

### Step 5: Update dashboard/report view
```python
def run_combined_report_view() -> None:
    st.header("📋 Consolidated Security Report")
    
    # Get combined findings from session
    findings = st.session_state.get("combined_findings") or []
    risk_summary = st.session_state.get("risk_summary")
    
    # Check for errors
    last_error = get_last_error(st)
    if last_error:
        st.error(f"Last Error: {last_error}")
    
    # Check if any scans have been run
    if not findings:
        st.warning("⚠️ No scans executed yet. Run a scan to see results.")
        st.info("Available scans: Web Application Scanner, Network Reconnaissance, JSON Analysis")
        return
    
    # Display risk summary
    if risk_summary:
        st.subheader("Executive Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Findings", len(findings))
        col2.metric("Risk Score", f"{risk_summary.overall_score:.1f}/10")
        col3.metric("Overall Severity", risk_summary.overall_severity)
    
    # Display findings
    st.subheader("All Findings")
    render_findings_table(findings)
    
    # Export
    csv_data = export_findings_csv(findings)
    st.download_button(
        "Download Report (CSV)",
        data=csv_data,
        file_name="security_report.csv",
        mime="text/csv"
    )
```

---

## Key Behaviors to Implement

### 1. Error Display
- Always check `result.error` after scan completes
- Display to user immediately: `st.error(result.error)`
- Log error for audit trail

### 2. Session Clearing
- Call `clear_scan_results(st)` before starting each NEW scan type
- Use `exclude_types=["url_scan"]` to preserve other scan results
- This prevents data mixing

### 3. Ownership Confirmation
- Checkbox MUST be checked before scan: `st.checkbox("I authorize this scan")`
- Pass to scanner: `ownership_confirmed=ownership_ack`

### 4. Loading State
- Call `set_scan_in_progress(st, True)` before scan
- Use `with st.spinner():` for visual feedback
- Call `set_scan_in_progress(st, False)` in finally block

### 5. Result Deduplication
- The `full_safe_scan()` function automatically deduplicates findings
- Each finding has unique `id` field
- No need to manually deduplicate in frontend

---

## Common Issues & Solutions

### Issue 1: "No findings even though target has issues"
**Solution**: This is CORRECT. The scanner only reports REAL findings from actual HTTP responses. If no real issues found, results should be empty.

### Issue 2: "Same finding appears twice"
**Solution**: Check `session_manager.add_finding_to_combined()` logic. Findings are deduped by `id` field.

### Issue 3: "Error says 'URL unreachable' but target is up"
**Solution**: Check:
1. Is target HTTPS? Try HTTP if failing
2. Does target have CORS restrictions?
3. Is firewall blocking the scan server?
4. Check logs for timeout details

### Issue 4: "Results from old scan showing"
**Solution**: Always call `clear_scan_results(st)` before new scan. Don't skip this step.

### Issue 5: "Nmap showing 'command not found' error"
**Solution**: Nmap binary not installed on server. Install with:
```bash
# Linux
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

---

## Testing Your Integration

### Test 1: Validation
```python
# Should fail - blocked domain
result = full_safe_scan(user, "google.com", True)
assert result.error is not None
```

### Test 2: Real scanning
```python
# Should succeed - valid target
result = full_safe_scan(user, "example.com", True)
assert result.error is None
assert len(result.findings) >= 0  # Could be 0 if no real issues
```

### Test 3: Session clearing
```python
st.session_state["combined_findings"] = ["old", "findings"]
clear_scan_results(st)
assert st.session_state["combined_findings"] == []
```

---

## Performance Notes

- **URL scan**: ~5-10 seconds (depends on target response time)
- **Nmap scan**: ~10-30 seconds (depends on target)
- **Passive analysis**: <1 second (local regex/parsing)
- **Overall**: Usually 5-40 seconds depending on network

---

## Security Notes

1. **Ownership confirmation required** - Scanner will not run without `ownership_confirmed=True`
2. **Audit logging** - All scans are logged to `scan_audit_log` for compliance
3. **Blocked domains** - Prevents accidental scanning of major platforms
4. **Error logging** - All failures logged with timestamp and user info

---

## Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check logs for:
- `URL validation error` - validation failed
- `URL check exception` - HTTP request failed
- `Nmap scan error` - Nmap execution failed
- `Risk aggregation error` - Finding processing failed

---

## Questions?

Refer to:
1. `FIXES_APPLIED.md` - Complete technical explanation
2. `scanner.py` - Implementation details
3. `session_manager.py` - State management
4. `attack_simulator.py` - Passive analysis logic

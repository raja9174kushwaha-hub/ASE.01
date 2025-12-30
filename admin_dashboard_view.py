import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import audit_manager
from models import Finding

def run_cyber_admin_dashboard():
    """
    Renders the Spec-Compliant RBAC Admin Dashboard using REAL DATA.
    Adapts to Dark/Light mode from session state.
    """
    
    # Check Theme
    light_mode = st.session_state.get("light_mode", False)
    
    # Theme Tokens
    if light_mode:
        text_color = "#1a1f36"
        sub_text = "#4b5563"
        card_bg = "#ffffff"
        card_border = "#e5e7eb"
        panel_bg = "#ffffff"
        plotly_template = "plotly_white"
        gauge_bg = "#f3f4f6"
        gauge_border = "#e5e7eb"
        # Light mode specific shadows for depth
        box_shadow = "0 2px 4px rgba(0,0,0,0.05)"
    else:
        text_color = "#ffffff"
        sub_text = "#8b949e"
        card_bg = "rgba(13, 17, 23, 0.8)"
        card_border = "#30363d"
        panel_bg = "rgba(13, 17, 23, 0.6)"
        plotly_template = "plotly_dark"
        gauge_bg = "#30363d"
        gauge_border = "#30363d"
        box_shadow = "0 4px 6px rgba(0,0,0,0.1)"

    # --- Custom CSS for the Dashboard Cards (Dynamic) ---
    st.markdown(f"""
    <style>
    /* Dashboard Grid Layout */
    .dashboard-container {{ display: flex; flex-direction: column; gap: 20px; }}
    
    /* Metric Card Styling */
    .metric-card {{
        background: {card_bg};
        border-radius: 8px;
        padding: 15px;
        border: 1px solid {card_border};
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        height: 100px;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(10px);
        box-shadow: {box_shadow};
        transition: transform 0.2s;
        color: {text_color};
    }}
    .metric-card:hover {{ transform: translateY(-2px); }}
    
    .card-blue {{ border-left: 4px solid #0052cc; }}
    .card-red {{ border-left: 4px solid #ff0055; }}
    .card-green {{ border-left: 4px solid #00ffcc; }}
    .card-orange {{ border-left: 4px solid #ff9900; }}
    
    .metric-value {{ font-size: 2.2em; font-weight: 700; color: {text_color}; line-height: 1; }}
    .metric-label {{ font-size: 0.85em; color: {sub_text}; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 5px; }}
    .metric-sub {{ font-size: 0.75em; color: {sub_text}; margin-top: auto; opacity: 0.8; }}
    
    /* Headers */
    .section-header {{
        color: {text_color};
        font-family: 'Inter', sans-serif;
        font-weight: 600;
        font-size: 1.1em;
        margin-bottom: 15px;
        border-left: 3px solid #00ffcc;
        padding-left: 10px;
    }}
    
    /* Panel Styling */
    .panel-box {{
        background: {panel_bg};
        border: 1px solid {card_border};
        border-radius: 8px;
        padding: 15px;
        height: 100%;
        box-shadow: {box_shadow};
    }}
    
    /* List Items */
    .threat-item {{
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid {card_border};
        font-size: 0.9em;
    }}
    .threat-item:last-child {{ border-bottom: none; }}
    .threat-name {{ color: {text_color}; }}
    .threat-val {{ color: #ff0055; font-weight: bold; }}
    
    /* Table Rows - Logs */
    .log-row {{
        font-family: monospace; 
        font-size: 0.85em; 
        color: {sub_text};
    }}
    </style>
    """, unsafe_allow_html=True)

    # --- 1. Fetch REAL Data ---
    findings: list[Finding] = st.session_state.get("combined_findings", [])
    logs = audit_manager.get_all_logs()
    
    # Calculate Metrics
    critical_count = sum(1 for f in findings if f.impact >= 4 and f.likelihood >= 4)
    sys_analyzed = len(set(l['user_email'] for l in logs)) if logs else 0
    
    # --- ROW 1: METRIC CARDS ---
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.markdown(f"""
        <div class="metric-card card-blue">
            <div class="metric-value">{len(findings)}</div>
            <div class="metric-label">Total Findings</div>
            <div class="metric-sub">From latest scan</div>
        </div>
        """, unsafe_allow_html=True)
    
    with c2:
        st.markdown(f"""
        <div class="metric-card card-red">
            <div class="metric-value">{critical_count}</div>
            <div class="metric-label">Critical Issues</div>
            <div class="metric-sub">Immediate Action Req.</div>
        </div>
        """, unsafe_allow_html=True)
        
    with c3:
        st.markdown(f"""
        <div class="metric-card card-green">
            <div class="metric-value">{sys_analyzed}</div>
            <div class="metric-label">Active Users</div>
            <div class="metric-sub">In Audit Logs</div>
        </div>
        """, unsafe_allow_html=True)
        
    with c4:
        st.markdown(f"""
        <div class="metric-card card-orange">
            <div class="metric-value">{len(logs)}</div>
            <div class="metric-label">Total Events</div>
            <div class="metric-sub">System Wide</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- ROW 2: RISK GAUGE | THREAT LIST (Real Data) ---
    col_risk, col_threat = st.columns([1, 1])

    with col_risk:
        st.markdown('<div class="section-header">Overall Risk Score</div>', unsafe_allow_html=True)
        
        # Calculate Real Risk Score based on findings
        if findings:
            total_score = sum(f.impact * f.likelihood for f in findings)
            max_possible = len(findings) * 25
            risk_score = min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0
        else:
            risk_score = 0
            
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = risk_score,
            title = {'text': "RISK INDEX", 'font': {'size': 14, 'color': "#ff0055"}},
            number = {'font': {'color': text_color, 'size': 40}},
            gauge = {
                'axis': {'range': [None, 100], 'visible': False},
                'bar': {'color': "#ff0055" if risk_score > 50 else "#00ffcc", 'thickness': 1},
                'bgcolor': "rgba(0,0,0,0)",
                'steps': [
                   {'range': [0, 60], 'color': gauge_bg},
                   {'range': [60, 100], 'color': gauge_border} 
                ],
            }
        ))
        
        fig_gauge.update_layout(
            template=plotly_template,
            paper_bgcolor="rgba(0,0,0,0)", 
            margin={"r":10,"t":10,"l":10,"b":10}, 
            height=250,
            font={'color': text_color}
        )
        
        st.markdown('<div class="panel-box" style="display:flex; align-items:center; justify-content:center;">', unsafe_allow_html=True)
        st.plotly_chart(fig_gauge, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_threat:
        st.markdown('<div class="section-header">Top Threats Found</div>', unsafe_allow_html=True)
        
        if not findings:
            # Color logic for "Empty State" text
            empty_color = sub_text
            threat_html = f"<div style='padding:10px; color:{empty_color};'>No active threats detected. System Clean.</div>"
        else:
             # Sort by severity
             top_findings = sorted(findings, key=lambda x: x.impact * x.likelihood, reverse=True)[:5]
             threat_html = ""
             for f in top_findings:
                 severity_color = "#ff0055" if (f.impact * f.likelihood) > 16 else "#ff9900"
                 severity_text = "Critical" if (f.impact * f.likelihood) > 16 else "High/Med"
                 threat_html += f"""
                 <div class="threat-item">
                     <span class="threat-name">{f.title[:30]}...</span>
                     <span class="threat-val" style="color:{severity_color}">{severity_text}</span>
                 </div>
                 """

        st.markdown(f"""
        <div class="panel-box">
            {threat_html}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- ROW 3: SYSTEM LOGS (Real) ---
    st.markdown('<div class="section-header">Real-Time System Logs</div>', unsafe_allow_html=True)
    
    # Format Logs Info HTML
    log_content = ""
    for entry in reversed(logs[-8:]): # Show last 8
        ts = entry.get("timestamp", "").split("T")[-1][:8]
        evt = entry.get("event_type", "UNKNOWN")
        email = entry.get("user_email", "system")
        
        color = text_color
        if "LOGIN" in evt: color = "#00ffcc" if not light_mode else "#0052cc"
        if "SCAN" in evt: color = "#0052cc"
        if "FAIL" in evt or "BLOCK" in evt: color = "#ff0055"
        
        log_content += f"<p style='color:{color}'>[{ts}] <b>{evt}</b> by {email}</p>"
        
    if not log_content:
        log_content = f"<p style='color:{sub_text}'>No logs available yet.</p>"

    st.markdown(f"""
    <div class="panel-box">
        <div class="log-row">
            {log_content}
        </div>
    </div>
    """, unsafe_allow_html=True)

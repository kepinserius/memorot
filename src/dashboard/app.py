import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

from src.audit.store import AuditStore
from src.quarantine.manager import QuarantineManager
from src.detection.pipeline import DetectionPipeline

st.set_page_config(page_title="Memory Poisoning Detection", layout="wide")

# Real-time auto-refresh option
st.sidebar.title("Configuration")
auto_refresh = st.sidebar.checkbox("Auto-refresh (every 5s)", value=False)
if auto_refresh:
    st.sidebar.caption("Auto-refresh active")
    st.empty()
    # Simple timeout reload
    import time
    time.sleep(5)
    st.rerun()

st.title("Memory Poisoning Detection Dashboard")

audit_store = AuditStore()
quarantine_manager = QuarantineManager(audit_store=audit_store)
detection_pipeline = DetectionPipeline(audit_store=audit_store)

# Top Metrics Row
events = audit_store.get_events(limit=1000)
pending_quarantine = quarantine_manager.get_pending_entries()

suspicious_count = sum(
    1 for e in events
    if "detection_result" in e.get("metadata", {})
    and e["metadata"]["detection_result"].get("decision") == "suspicious"
)

malicious_count = sum(
    1 for e in events
    if "detection_result" in e.get("metadata", {})
    and e["metadata"]["detection_result"].get("decision") == "malicious"
)

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Events", len(events))
with col2:
    st.metric("Pending Quarantine", len(pending_quarantine))
with col3:
    st.metric("Suspicious Events", suspicious_count)
with col4:
    st.metric("Malicious Events", malicious_count)

st.divider()

# Main Tabs
tabs = st.tabs(["Live Events & Filter", "Detection Insights", "Quarantine Manager", "Audit Trail", "System Status"])

with tabs[0]:
    st.subheader("Memory Events Stream")
    
    # Advanced Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        source_filter = st.multiselect(
            "Filter by Source Type",
            options=list(set(e.get("source_type", "unknown") for e in events)) if events else [],
            default=[]
        )
    with col_f2:
        trust_range = st.slider("Filter by Trust Level Range", 0.0, 1.0, (0.0, 1.0))
    with col_f3:
        search_term = st.text_input("Search Content", "")
        
    filtered_events = events
    if source_filter:
        filtered_events = [e for e in filtered_events if e.get("source_type") in source_filter]
    if trust_range:
        filtered_events = [e for e in filtered_events if trust_range[0] <= e.get("trust_level", 0.0) <= trust_range[1]]
    if search_term:
        filtered_events = [e for e in filtered_events if search_term.lower() in e.get("content", "").lower()]

    if filtered_events:
        df_events = pd.DataFrame([
            {
                "ID": e["id"][:8],
                "Content": e.get("content", ""),
                "Source": e.get("source_type", "unknown"),
                "Trust Level": f"{e.get('trust_level', 0):.2f}",
                "Session": e.get("session_id", "N/A"),
                "Timestamp": e.get("timestamp", ""),
            }
            for e in filtered_events[:100]
        ])
        st.dataframe(df_events, use_container_width=True)
    else:
        st.info("No matching events found")

with tabs[1]:
    st.subheader("Detection Layer Analytics")
    
    detection_decisions = {}
    for event in events:
        metadata = event.get("metadata", {})
        detection_result = metadata.get("detection_result", {})
        decision = detection_result.get("decision", "unknown")
        detection_decisions[decision] = detection_decisions.get(decision, 0) + 1
    
    if detection_decisions:
        col1, col2 = st.columns(2)
        with col1:
            fig_pie = go.Figure(data=[go.Pie(
                labels=list(detection_decisions.keys()),
                values=list(detection_decisions.values()),
                hole=0.4
            )])
            fig_pie.update_layout(title="Decision Breakdown", height=350)
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            detector_types = {}
            for event in events:
                metadata = event.get("metadata", {})
                detector = metadata.get("detector_type", "unknown")
                detector_types[detector] = detector_types.get(detector, 0) + 1
            
            fig_bar = go.Figure(data=[go.Bar(
                x=list(detector_types.keys()),
                y=list(detector_types.values()),
            )])
            fig_bar.update_layout(title="Triggered Detectors", height=350)
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No detection results to analyze")

with tabs[2]:
    st.subheader("Quarantine Management Console")
    
    col_q1, col_q2 = st.columns([2, 1])
    
    with col_q1:
        st.write(f"**Action Required ({len(pending_quarantine)} items):**")
        if pending_quarantine:
            for entry in pending_quarantine[:15]:
                with st.expander(f"Entry {entry.id[:8]} | Score: {entry.suspicion_score:.2f}"):
                    st.write(f"**Event ID:** `{entry.event_id}`")
                    st.write(f"**Reason:** {entry.suspicion_reason}")
                    st.write(f"**Expires in:** {entry.hours_remaining:.1f} hours")
                    
                    btn_col1, btn_col2 = st.columns(2)
                    with btn_col1:
                        if st.button("Approve & Commit", key=f"verify_{entry.id}"):
                            quarantine_manager.verify_entry(entry.id, verified=True)
                            st.success("Entry marked as verified!")
                            st.rerun()
                    with btn_col2:
                        if st.button("Reject & Purge", key=f"reject_{entry.id}"):
                            quarantine_manager.verify_entry(entry.id, verified=False)
                            st.error("Entry rejected and purged.")
                            st.rerun()
        else:
            st.success("Quarantine queue is empty!")
            
    with col_q2:
        st.write("**Summary Status**")
        expired = quarantine_manager.get_expired_entries()
        st.metric("Expired/Purged", len(expired))
        verified_count = sum(
            1 for e in quarantine_manager.entries.values()
            if e.verification_status.value == "verified"
        )
        st.metric("Approved Entries", verified_count)

with tabs[3]:
    st.subheader("Immutable Audit Trail")
    session_filter = st.text_input("Filter by exact Session ID")
    
    audit_events = audit_store.get_events(session_id=session_filter if session_filter else None, limit=200)
    
    if audit_events:
        df_audit = pd.DataFrame([
            {
                "Event ID": e["id"],
                "Source": e.get("source_type", ""),
                "Trust Level": e.get("trust_level", 0),
                "Session": e.get("session_id", ""),
                "Timestamp": e.get("timestamp", ""),
            }
            for e in audit_events
        ])
        st.dataframe(df_audit, use_container_width=True)
    else:
        st.info("No matching audit logs")

with tabs[4]:
    st.subheader("System Architecture & Status")
    st.markdown("""
    - **Layer 1: Instrumentation**: ACTIVE (Capturing source, trust score, session metadata)
    - **Layer 2: Detection Pipeline**: ACTIVE (Provenance, Semantic Drift, Outlier, Rules)
    - **Layer 3: Quarantine Engine**: ACTIVE (Time-decay verification workflow)
    - **Layer 4: Audit & Rollback**: ACTIVE (SQLite-backed Event Sourcing)
    """)

st.divider()
col_d1, col_d2 = st.columns(2)
with col_d1:
    if st.button("Manual Refresh"):
        st.rerun()
with col_d2:
    csv_data = pd.DataFrame(events).to_csv(index=False)
    st.download_button(
        label="Export Audit Events (CSV)",
        data=csv_data,
        file_name=f"audit_events_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )


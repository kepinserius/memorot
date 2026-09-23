import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from typing import Dict, Any, List

from src.audit.store import AuditStore
from src.quarantine.manager import QuarantineManager
from src.detection.pipeline import DetectionPipeline

st.set_page_config(page_title="Memory Poisoning Detection", layout="wide")

st.title(" Memory Poisoning Detection Dashboard")

audit_store = AuditStore()
quarantine_manager = QuarantineManager(audit_store=audit_store)
detection_pipeline = DetectionPipeline(audit_store=audit_store)

col1, col2, col3, col4 = st.columns(4)

events = audit_store.get_events(limit=1000)
with col1:
    st.metric("Total Events", len(events))

pending_quarantine = quarantine_manager.get_pending_entries()
with col2:
    st.metric("Pending Verification", len(pending_quarantine))

suspicious_count = sum(
    1 for e in events
    if "detection_result" in e.get("metadata", {})
    and e["metadata"]["detection_result"].get("decision") == "suspicious"
)
with col3:
    st.metric("Suspicious Events", suspicious_count)

malicious_count = sum(
    1 for e in events
    if "detection_result" in e.get("metadata", {})
    and e["metadata"]["detection_result"].get("decision") == "malicious"
)
with col4:
    st.metric("Malicious Events", malicious_count)

st.divider()

tabs = st.tabs(["Events", "Detection Results", "Quarantine", "Audit Trail"])

with tabs[0]:
    st.subheader("Recent Memory Events")
    
    if events:
        df_events = pd.DataFrame([
            {
                "ID": e["id"][:8],
                "Content": e.get("content", "")[:50],
                "Source": e.get("source_type", "unknown"),
                "Trust": f"{e.get('trust_level', 0):.2f}",
                "Timestamp": e.get("timestamp", ""),
            }
            for e in events[:50]
        ])
        
        st.dataframe(df_events, use_container_width=True)
    else:
        st.info("No events recorded yet")

with tabs[1]:
    st.subheader("Detection Results")
    
    detection_decisions = {}
    for event in events:
        metadata = event.get("metadata", {})
        detection_result = metadata.get("detection_result", {})
        decision = detection_result.get("decision", "unknown")
        detection_decisions[decision] = detection_decisions.get(decision, 0) + 1
    
    if detection_decisions:
        col1, col2 = st.columns([1, 1])
        
        with col1:
            fig_pie = go.Figure(data=[go.Pie(
                labels=list(detection_decisions.keys()),
                values=list(detection_decisions.values()),
                marker=dict(colors=["green", "orange", "red"])
            )])
            fig_pie.update_layout(title="Detection Decision Distribution", height=400)
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
                marker_color="lightblue"
            )])
            fig_bar.update_layout(title="Detections by Type", height=400)
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No detection results yet")

with tabs[2]:
    st.subheader("Quarantine Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Pending Verification:** {len(pending_quarantine)}")
        
        if pending_quarantine:
            for entry in pending_quarantine[:10]:
                with st.expander(f"Entry {entry.id[:8]} - Trust: {entry.suspicion_score:.2f}"):
                    st.write(f"Event ID: {entry.event_id}")
                    st.write(f"Reason: {entry.suspicion_reason}")
                    st.write(f"Hours Remaining: {entry.hours_remaining:.1f}")
                    
                    col_verify, col_reject = st.columns(2)
                    with col_verify:
                        if st.button(f"Verify##verify_{entry.id}", key=f"verify_{entry.id}"):
                            quarantine_manager.verify_entry(entry.id, verified=True)
                            st.success("Entry verified")
                    
                    with col_reject:
                        if st.button(f"Reject##reject_{entry.id}", key=f"reject_{entry.id}"):
                            quarantine_manager.verify_entry(entry.id, verified=False)
                            st.error("Entry rejected")
        else:
            st.info("No entries in quarantine")
    
    with col2:
        st.write("**Quarantine Statistics**")
        
        expired = quarantine_manager.get_expired_entries()
        st.write(f"Expired (auto-reject): {len(expired)}")
        
        verified = sum(
            1 for e in quarantine_manager.entries.values()
            if e.verification_status.value == "verified"
        )
        st.write(f"Verified: {verified}")

with tabs[3]:
    st.subheader("Audit Trail")
    
    session_filter = st.text_input("Filter by Session ID (optional)")
    
    if session_filter:
        audit_events = audit_store.get_events(session_id=session_filter, limit=100)
    else:
        audit_events = audit_store.get_events(limit=100)
    
    if audit_events:
        df_audit = pd.DataFrame([
            {
                "ID": e["id"][:8],
                "Source Type": e.get("source_type", ""),
                "Trust": f"{e.get('trust_level', 0):.2f}",
                "Session": e.get("session_id", "")[:8],
                "Timestamp": e.get("timestamp", ""),
            }
            for e in audit_events
        ])
        
        st.dataframe(df_audit, use_container_width=True)
    else:
        st.info("No audit events found")

st.divider()

col1, col2 = st.columns(2)

with col1:
    if st.button("Refresh Dashboard"):
        st.rerun()

with col2:
    if st.button("Export Report (CSV)"):
        csv_data = pd.DataFrame(events).to_csv(index=False)
        st.download_button(
            label="Download Events CSV",
            data=csv_data,
            file_name=f"memory_events_{datetime.now().isoformat()}.csv",
        )

st.info("Dashboard updates every 30 seconds. Refresh button for manual update.")

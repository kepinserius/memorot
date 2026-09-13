import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from typing import List, Dict, Any
from datetime import datetime, timedelta


def create_trust_distribution_chart(events: List[Dict[str, Any]]) -> go.Figure:
    trust_levels = [e.get("trust_level", 0) for e in events if "trust_level" in e]
    
    if not trust_levels:
        return go.Figure()
    
    fig = go.Figure(data=[go.Histogram(
        x=trust_levels,
        nbinsx=20,
        marker_color="blue",
        opacity=0.7,
    )])
    
    fig.update_layout(
        title="Trust Level Distribution",
        xaxis_title="Trust Level",
        yaxis_title="Count",
        height=400,
    )
    
    return fig


def create_timeline_chart(events: List[Dict[str, Any]]) -> go.Figure:
    if not events:
        return go.Figure()
    
    df = pd.DataFrame([
        {
            "timestamp": datetime.fromisoformat(e["timestamp"]) if isinstance(e.get("timestamp"), str) else e.get("timestamp"),
            "source_type": e.get("source_type", "unknown"),
        }
        for e in events if "timestamp" in e
    ])
    
    if df.empty:
        return go.Figure()
    
    df = df.sort_values("timestamp")
    df["hour"] = df["timestamp"].dt.floor("H")
    
    hourly_counts = df.groupby(["hour", "source_type"]).size().reset_index(name="count")
    
    fig = px.bar(
        hourly_counts,
        x="hour",
        y="count",
        color="source_type",
        title="Memory Events Timeline",
        labels={"hour": "Time", "count": "Events"},
    )
    
    fig.update_layout(height=400)
    
    return fig


def create_detection_heatmap(events: List[Dict[str, Any]]) -> go.Figure:
    detector_results = {}
    
    for event in events:
        metadata = event.get("metadata", {})
        detection_result = metadata.get("detection_result", {})
        
        if not detection_result:
            continue
        
        individual_results = detection_result.get("details", {}).get("individual_results", [])
        
        for result in individual_results:
            detector = result.get("detector_type", "unknown")
            decision = result.get("decision", "unknown")
            
            key = f"{detector}_{decision}"
            detector_results[key] = detector_results.get(key, 0) + 1
    
    if not detector_results:
        return go.Figure()
    
    detectors = list(set(k.split("_")[0] for k in detector_results.keys()))
    decisions = ["clean", "suspicious", "malicious"]
    
    z_data = []
    for detector in detectors:
        row = []
        for decision in decisions:
            key = f"{detector}_{decision}"
            row.append(detector_results.get(key, 0))
        z_data.append(row)
    
    fig = go.Figure(data=go.Heatmap(
        z=z_data,
        x=decisions,
        y=detectors,
        colorscale="RdYlGn_r",
        text=z_data,
        texttemplate="%{text}",
        textfont={"size": 12},
    ))
    
    fig.update_layout(
        title="Detection Results by Detector Type",
        xaxis_title="Decision",
        yaxis_title="Detector",
        height=400,
    )
    
    return fig


def create_quarantine_aging_chart(quarantine_stats: Dict[str, Any]) -> go.Figure:
    aging_dist = quarantine_stats.get("aging_distribution", {})
    
    if not aging_dist:
        return go.Figure()
    
    labels = list(aging_dist.keys())
    values = list(aging_dist.values())
    
    fig = go.Figure(data=[go.Bar(
        x=labels,
        y=values,
        marker_color=["green", "yellow", "orange", "red"],
    )])
    
    fig.update_layout(
        title="Quarantine Aging Distribution",
        xaxis_title="Time in Quarantine",
        yaxis_title="Count",
        height=400,
    )
    
    return fig


def create_suspicion_score_chart(events: List[Dict[str, Any]]) -> go.Figure:
    suspicion_scores = []
    
    for event in events:
        metadata = event.get("metadata", {})
        detection_result = metadata.get("detection_result", {})
        
        if detection_result and "suspicion_score" in detection_result:
            suspicion_scores.append(detection_result["suspicion_score"])
    
    if not suspicion_scores:
        return go.Figure()
    
    fig = go.Figure(data=[go.Box(
        y=suspicion_scores,
        name="Suspicion Score",
        marker_color="red",
        boxmean=True,
    )])
    
    fig.update_layout(
        title="Suspicion Score Distribution",
        yaxis_title="Score",
        height=400,
    )
    
    return fig

"""
Analytics API endpoint for XGuard.
Provides aggregated security metrics, time-series data, threat distribution,
performance telemetry, detection effectiveness, and recent security events.
All data is derived from real ScanRecord history — no mock values.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case

from app.database.session import get_db
from app.database.models import ScanRecord, FeedbackRecord

router = APIRouter(prefix="/analytics", tags=["Analytics"])


def _period_bounds(period: str):
    """Return (start_dt, end_dt) for the requested time period."""
    now = datetime.now(timezone.utc)
    if period == "24h":
        start = now - timedelta(hours=24)
    elif period == "7d":
        start = now - timedelta(days=7)
    elif period == "30d":
        start = now - timedelta(days=30)
    else:  # "all"
        start = None
    return start, now


def _prev_period_bounds(period: str, current_start, current_end):
    """Return (start_dt, end_dt) for the equivalent previous period."""
    if current_start is None:
        return None, None
    duration = current_end - current_start
    return current_start - duration, current_start


@router.get("/summary")
def get_analytics_summary(
    period: str = Query("7d", regex="^(24h|7d|30d|all)$"),
    db: Session = Depends(get_db)
):
    """
    Security summary metrics for the selected time period.
    Compares current period vs previous period where data exists.
    """
    start, end = _period_bounds(period)
    prev_start, prev_end = _prev_period_bounds(period, start, end)

    def query_period(s, e):
        q = db.query(ScanRecord)
        if s:
            q = q.filter(ScanRecord.timestamp >= s, ScanRecord.timestamp < e)
        return q.all()

    records = query_period(start, end)
    prev_records = query_period(prev_start, prev_end) if prev_start else []

    def compute_metrics(recs):
        total = len(recs)
        cats = [r.predicted_category or "unknown" for r in recs]
        threats_blocked = sum(
            1 for r in recs
            if r.recommended_action in ("block",) or r.risk_level in ("high", "critical")
        )
        suspicious = sum(1 for r in recs if r.risk_level == "medium")
        benign = sum(
            1 for r in recs
            if r.risk_level == "low" and (r.predicted_category or "").lower() in ("benign", "safe", "")
        )
        unknown = sum(
            1 for r in recs
            if (r.predicted_category or "unknown").lower() in ("unknown", "")
            and r.risk_level == "low"
        )
        detection_rate = round((threats_blocked / total * 100), 1) if total > 0 else 0.0
        latencies = [r.scan_duration_ms for r in recs if r.scan_duration_ms and r.scan_duration_ms > 0]
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None
        overrides = sum(1 for r in recs if r.user_action == "overridden")
        return {
            "total": total,
            "threats_blocked": threats_blocked,
            "suspicious": suspicious,
            "benign": benign,
            "unknown": unknown,
            "detection_rate": detection_rate,
            "avg_latency_ms": avg_latency,
            "overrides": overrides,
        }

    curr = compute_metrics(records)
    prev = compute_metrics(prev_records) if prev_records else None

    def delta(key):
        if prev is None:
            return None
        c, p = curr[key], prev[key]
        if p == 0:
            return None
        return round(((c - p) / p) * 100, 1)

    return {
        "period": period,
        "total_scans": curr["total"],
        "total_scans_delta_pct": delta("total"),
        "threats_blocked": curr["threats_blocked"],
        "threats_blocked_delta_pct": delta("threats_blocked"),
        "suspicious_urls": curr["suspicious"],
        "suspicious_delta_pct": delta("suspicious"),
        "benign_urls": curr["benign"],
        "unknown_urls": curr["unknown"],
        "detection_rate": curr["detection_rate"],
        "avg_latency_ms": curr["avg_latency_ms"],
        "user_overrides": curr["overrides"],
    }


@router.get("/timeseries")
def get_timeseries(
    period: str = Query("7d", regex="^(24h|7d|30d|all)$"),
    db: Session = Depends(get_db)
):
    """
    Scan activity time-series for the selected period.
    Returns bucketed data points with total scans, suspicious, and blocked counts.
    """
    start, end = _period_bounds(period)

    q = db.query(ScanRecord)
    if start:
        q = q.filter(ScanRecord.timestamp >= start)
    records = q.order_by(ScanRecord.timestamp).all()

    if not records:
        return {"period": period, "buckets": [], "peak_label": None, "total": 0, "summary": None}

    # Determine bucket granularity
    if period == "24h":
        bucket_hours = 2
        fmt = "%H:%M"
        label_fn = lambda dt: dt.strftime("%H:%M")
    elif period == "7d":
        bucket_hours = 24
        fmt = "%a"
        label_fn = lambda dt: dt.strftime("%a")
    elif period == "30d":
        bucket_hours = 24
        fmt = "%b %d"
        label_fn = lambda dt: dt.strftime("%b %d")
    else:
        # For "all", use weekly buckets
        bucket_hours = 24 * 7
        label_fn = lambda dt: dt.strftime("%b %d")

    # Build bucket list
    if start:
        bucket_start = start
    else:
        oldest = records[0].timestamp
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        bucket_start = oldest

    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)

    buckets = []
    current = bucket_start
    while current < end:
        bucket_end = current + timedelta(hours=bucket_hours)
        buckets.append({"start": current, "end": bucket_end, "label": label_fn(current),
                        "total": 0, "suspicious": 0, "blocked": 0})
        current = bucket_end

    # Assign records to buckets
    for rec in records:
        ts = rec.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        for bucket in buckets:
            if bucket["start"] <= ts < bucket["end"]:
                bucket["total"] += 1
                if rec.risk_level == "medium":
                    bucket["suspicious"] += 1
                if rec.risk_level in ("high", "critical") or rec.recommended_action == "block":
                    bucket["blocked"] += 1
                break

    # Find peak
    peak_bucket = max(buckets, key=lambda b: b["total"]) if buckets else None

    result_buckets = [
        {
            "label": b["label"],
            "total": b["total"],
            "suspicious": b["suspicious"],
            "blocked": b["blocked"]
        }
        for b in buckets
    ]

    return {
        "period": period,
        "buckets": result_buckets,
        "peak_label": peak_bucket["label"] if peak_bucket and peak_bucket["total"] > 0 else None,
        "total": len(records),
    }


@router.get("/categories")
def get_category_distribution(
    period: str = Query("7d", regex="^(24h|7d|30d|all)$"),
    db: Session = Depends(get_db)
):
    """
    Threat category distribution for the selected period.
    Each record is counted once using its primary predicted_category.
    """
    start, _ = _period_bounds(period)
    q = db.query(ScanRecord)
    if start:
        q = q.filter(ScanRecord.timestamp >= start)
    records = q.all()

    total = len(records)
    cat_counts = {}
    for r in records:
        cat = (r.predicted_category or "unknown").lower()
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    categories = []
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        pct = round((count / total) * 100, 1) if total > 0 else 0.0
        categories.append({
            "category": cat,
            "count": count,
            "percentage": pct,
        })

    return {
        "period": period,
        "total": total,
        "categories": categories,
    }


@router.get("/telemetry")
def get_performance_telemetry(
    period: str = Query("7d", regex="^(24h|7d|30d|all)$"),
    db: Session = Depends(get_db)
):
    """
    Performance and detection engine telemetry for the selected period.
    """
    start, _ = _period_bounds(period)
    q = db.query(ScanRecord)
    if start:
        q = q.filter(ScanRecord.timestamp >= start)
    records = q.all()

    latencies = sorted([
        r.scan_duration_ms for r in records
        if r.scan_duration_ms is not None and r.scan_duration_ms > 0
    ])

    def percentile(data, p):
        if not data:
            return None
        idx = int(len(data) * p / 100)
        idx = min(idx, len(data) - 1)
        return round(data[idx], 2)

    avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else None
    median_lat = percentile(latencies, 50)
    p95_lat = percentile(latencies, 95)

    total = len(records)
    failed = sum(1 for r in records if r.checks_failed_json and json.loads(r.checks_failed_json or "[]"))
    successful = total - failed
    success_rate = round((successful / total) * 100, 1) if total > 0 else None

    overrides = sum(1 for r in records if r.user_action == "overridden")
    blocked_nav = sum(1 for r in records if r.recommended_action == "block")
    warned = sum(1 for r in records if r.recommended_action == "warn")
    override_rate = round((overrides / total) * 100, 1) if total > 0 else None

    # Most recent scan timestamp
    latest = max((r.timestamp for r in records), default=None)
    latest_iso = latest.isoformat() if latest else None

    return {
        "period": period,
        "scan_performance": {
            "avg_latency_ms": avg_lat,
            "median_latency_ms": median_lat,
            "p95_latency_ms": p95_lat,
            "successful_scans": successful,
            "failed_scans": failed,
            "success_rate_pct": success_rate,
            "total_scans": total,
        },
        "user_interaction": {
            "total_overrides": overrides,
            "override_rate_pct": override_rate,
            "blocked_navigations": blocked_nav,
            "warned_navigations": warned,
        },
        "detection_engine": {
            "last_successful_scan": latest_iso,
        }
    }


@router.get("/trends")
def get_threat_trends(
    period: str = Query("7d", regex="^(24h|7d|30d|all)$"),
    db: Session = Depends(get_db)
):
    """
    Actionable threat intelligence insights derived from real scan history.
    """
    start, end = _period_bounds(period)
    prev_start, prev_end = _prev_period_bounds(period, start, end)

    q = db.query(ScanRecord)
    if start:
        q = q.filter(ScanRecord.timestamp >= start)
    records = q.all()

    prev_q = db.query(ScanRecord)
    if prev_start:
        prev_q = prev_q.filter(ScanRecord.timestamp >= prev_start,
                                ScanRecord.timestamp < prev_end)
    prev_records = prev_q.all() if prev_start else []

    insights = []
    total = len(records)

    if total == 0:
        return {"period": period, "insights": [], "data_available": False}

    # Most common threat category (excluding benign/unknown)
    threat_cats = {}
    for r in records:
        cat = (r.predicted_category or "unknown").lower()
        if cat not in ("benign", "unknown", "safe", ""):
            threat_cats[cat] = threat_cats.get(cat, 0) + 1

    if threat_cats:
        top_cat = max(threat_cats, key=threat_cats.get)
        top_cat_count = threat_cats[top_cat]
        insights.append({
            "id": "top_threat_category",
            "title": "Top Threat Category",
            "metric": f"{top_cat.replace('_', ' ').title()} ({top_cat_count} detections)",
            "period": period,
            "severity": "high" if top_cat_count > 5 else "medium",
            "explanation": f"'{top_cat.replace('_', ' ').title()}' is the most frequently detected threat pattern in the selected period."
        })

    # Suspicious activity trend
    curr_suspicious = sum(1 for r in records if r.risk_level == "medium")
    prev_suspicious = sum(1 for r in prev_records if r.risk_level == "medium")

    if prev_suspicious > 0 and curr_suspicious != prev_suspicious:
        pct_change = round(((curr_suspicious - prev_suspicious) / prev_suspicious) * 100, 0)
        direction = "increased" if pct_change > 0 else "decreased"
        sev = "high" if pct_change > 50 else ("medium" if pct_change > 0 else "info")
        insights.append({
            "id": "suspicious_trend",
            "title": "Suspicious URL Activity",
            "metric": f"{abs(int(pct_change))}% {direction} vs previous period",
            "period": period,
            "severity": sev,
            "explanation": f"Suspicious URL detections have {direction} by {abs(int(pct_change))}% compared to the previous equivalent period ({prev_suspicious} → {curr_suspicious})."
        })
    elif curr_suspicious > 0:
        insights.append({
            "id": "suspicious_count",
            "title": "Suspicious URLs Detected",
            "metric": f"{curr_suspicious} flagged",
            "period": period,
            "severity": "medium" if curr_suspicious > 3 else "info",
            "explanation": f"{curr_suspicious} URLs were classified as suspicious in the selected period."
        })

    # Repeated domains
    domain_counts = {}
    for r in records:
        if r.registered_domain:
            domain_counts[r.registered_domain] = domain_counts.get(r.registered_domain, 0) + 1
    repeat_flagged = {
        d: c for d, c in domain_counts.items()
        if c > 1 and any(
            r.risk_level in ("medium", "high", "critical")
            for r in records if r.registered_domain == d
        )
    }
    if repeat_flagged:
        top_repeat = max(repeat_flagged, key=repeat_flagged.get)
        insights.append({
            "id": "repeat_flagged_domain",
            "title": "Repeated Suspicious Domain",
            "metric": f"{top_repeat} visited {repeat_flagged[top_repeat]}× and flagged",
            "period": period,
            "severity": "high",
            "explanation": f"The domain '{top_repeat}' was scanned {repeat_flagged[top_repeat]} times and flagged as suspicious or risky. Repeated access to flagged domains increases risk."
        })

    # High-risk count
    high_risk = sum(1 for r in records if r.risk_level in ("high", "critical"))
    if high_risk > 0:
        insights.append({
            "id": "high_risk_count",
            "title": "High-Risk URLs Encountered",
            "metric": f"{high_risk} high-risk destination{'s' if high_risk != 1 else ''}",
            "period": period,
            "severity": "high" if high_risk > 3 else "medium",
            "explanation": f"{high_risk} URLs were classified as high-risk or critical in the selected period."
        })

    # Override behavior
    overrides = sum(1 for r in records if r.user_action == "overridden")
    if overrides > 0:
        override_rate = round((overrides / total) * 100, 1)
        insights.append({
            "id": "user_overrides",
            "title": "Security Warning Bypasses",
            "metric": f"{overrides} override{'s' if overrides != 1 else ''} ({override_rate}% of scans)",
            "period": period,
            "severity": "medium" if override_rate > 10 else "info",
            "explanation": f"Users bypassed {overrides} security warning{'s' if overrides != 1 else ''}. High override rates may indicate alert fatigue or misconfiguration."
        })

    return {
        "period": period,
        "insights": insights,
        "data_available": len(records) > 0
    }


@router.get("/recent-events")
def get_recent_events(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db)
):
    """
    Recent security events — threats, overrides, and scan failures.
    Redacts sensitive query parameters from displayed URLs.
    """
    records = db.query(ScanRecord).order_by(desc(ScanRecord.timestamp)).limit(limit).all()

    events = []
    for r in records:
        # Determine event type
        if r.risk_level in ("high", "critical"):
            event_type = "threat_detected"
            action_label = "Blocked" if r.recommended_action == "block" else "Warned"
        elif r.risk_level == "medium":
            event_type = "suspicious_detected"
            action_label = "Flagged"
        elif r.user_action == "overridden":
            event_type = "override_recorded"
            action_label = "Override"
        elif r.checks_failed_json and json.loads(r.checks_failed_json or "[]"):
            event_type = "scan_failure"
            action_label = "Scan Error"
        else:
            event_type = "benign_scan"
            action_label = "Allowed"

        # Safely redact URL query string
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(r.url)
            safe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        except Exception:
            safe_url = r.registered_domain or r.hostname or "unknown"

        events.append({
            "scan_id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "domain": r.registered_domain or r.hostname or "unknown",
            "safe_url": safe_url,
            "risk_level": r.risk_level,
            "risk_score": r.risk_score,
            "category": r.predicted_category or "unknown",
            "event_type": event_type,
            "action": action_label,
            "user_action": r.user_action,
        })

    return {"events": events, "total": len(events)}


@router.get("/effectiveness")
def get_detection_effectiveness(
    db: Session = Depends(get_db)
):
    """
    Detection effectiveness metrics derived from feedback (false positive / negative reports)
    and confirmed scan outcomes. Model evaluation metrics from ml_adapter are shown separately.
    """
    total_scans = db.query(ScanRecord).count()
    feedback_records = db.query(FeedbackRecord).all()

    fp_count = sum(1 for f in feedback_records if f.feedback_type == "false_positive")
    fn_count = sum(1 for f in feedback_records if f.feedback_type == "false_negative")

    confirmed_threats = db.query(ScanRecord).filter(
        ScanRecord.risk_level.in_(["high", "critical"])
    ).count()

    # Precision / Recall can only be calculated with labelled ground truth (feedback)
    total_feedback = fp_count + fn_count
    precision = None
    recall = None
    f1 = None

    if confirmed_threats > 0 and total_feedback > 0:
        # Approximate: TP = confirmed_threats - fn_count, FP = fp_count
        tp = max(0, confirmed_threats - fn_count)
        fp = fp_count
        fn = fn_count
        if (tp + fp) > 0:
            precision = round(tp / (tp + fp), 3)
        if (tp + fn) > 0:
            recall = round(tp / (tp + fn), 3)
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1 = round(2 * precision * recall / (precision + recall), 3)

    return {
        "total_scans": total_scans,
        "confirmed_threat_detections": confirmed_threats,
        "false_positive_reports": fp_count,
        "false_negative_reports": fn_count,
        "total_feedback_reports": total_feedback,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "note": "Precision, Recall, and F1 are estimated from user feedback reports only. They are NOT derived from general scan counts.",
    }

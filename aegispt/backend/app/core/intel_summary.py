"""Shared engagement intelligence & port aggregator for API, CLI, and Reports."""
from __future__ import annotations

from typing import Any

from app.tools.intel_extractor import mask_value


def _port_records_from_asset(asset: Any) -> list[dict[str, Any]]:
    """Extract normalized port records from an Asset's headers and technologies."""
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers = getattr(asset, "headers", None) or {}
    raw_ports = headers.get("ports") if isinstance(headers, dict) else None
    if isinstance(raw_ports, list):
        for rec in raw_ports:
            if not isinstance(rec, dict) or "port" not in rec:
                continue
            p_num = rec.get("port")
            proto = str(rec.get("proto") or "tcp")
            key = (str(p_num), proto)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "port": p_num,
                    "proto": proto,
                    "state": str(rec.get("state") or "open"),
                    "service": str(rec.get("service") or ""),
                    "product": str(rec.get("product") or ""),
                    "version": str(rec.get("version") or ""),
                    "banner": str(rec.get("banner") or ""),
                }
            )

    for tech in getattr(asset, "technologies", None) or []:
        t_str = str(tech)
        if not t_str.startswith("port:"):
            continue
        # Format: port:80/tcp or port:80/tcp:http (nginx 1.18.0)
        body = t_str[5:]
        banner = ""
        if " (" in body and body.endswith(")"):
            body, banner = body.split(" (", 1)
            banner = banner[:-1].strip()
        parts = body.split(":", 1)
        port_proto = parts[0]
        svc = parts[1] if len(parts) > 1 else ""
        if "/" in port_proto:
            p_str, proto = port_proto.split("/", 1)
        else:
            p_str, proto = port_proto, "tcp"
        key = (p_str, proto)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "port": int(p_str) if p_str.isdigit() else p_str,
                "proto": proto,
                "state": "open",
                "service": svc,
                "product": "",
                "version": "",
                "banner": banner,
            }
        )
    return sorted(records, key=lambda x: (int(x["port"]) if str(x["port"]).isdigit() else 99999, str(x["proto"])))


def build_intel_summary(
    *,
    engagement: Any,
    assets: list[Any],
    endpoints: list[Any],
    findings: list[Any],
    runs: list[Any],
) -> dict[str, Any]:
    """Aggregate deduplicated flags, keys, credentials, IDs, names, IPs, ports, and versions."""
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    open_ports: list[dict[str, Any]] = []

    def _add_item(
        *,
        category: str,
        label: str,
        value: str,
        masked_value: str | None = None,
        sensitive: bool = False,
        location: str = "",
        tool_source: str = "aegispt",
        finding_id: str | None = None,
        asset_id: str | None = None,
    ) -> None:
        val_s = str(value or "").strip()
        if not val_s:
            return
        dedupe = (category, label, val_s)
        if dedupe in seen:
            return
        seen.add(dedupe)
        items.append(
            {
                "category": category,
                "label": label,
                "value": val_s,
                "masked_value": masked_value if masked_value is not None else (mask_value(val_s) if sensitive else val_s),
                "sensitive": sensitive,
                "location": location,
                "tool_source": tool_source,
                "finding_id": finding_id,
                "asset_id": asset_id,
            }
        )

    # 1. Engagement-level identifier & numeric context
    if engagement is not None:
        _add_item(
            category="identifier",
            label="Engagement ID",
            value=str(getattr(engagement, "id", "")),
            location="engagement",
            tool_source="system",
        )

    # 2. Assets: IP addresses, hostnames, titles, ports, status codes, versions/tech
    for a in assets:
        host_val = str(getattr(a, "value", "") or "")
        a_id = str(getattr(a, "id", "") or "")
        src = str(getattr(a, "discovered_by", "") or "recon")
        if host_val:
            _add_item(
                category="name",
                label=f"Asset ({getattr(a, 'asset_type', 'host')})",
                value=host_val,
                location=a_id,
                tool_source=src,
                asset_id=a_id,
            )
        ip_addr = getattr(a, "ip_address", None)
        if ip_addr:
            _add_item(
                category="number",
                label="Host IP Address",
                value=str(ip_addr),
                location=host_val,
                tool_source=src,
                asset_id=a_id,
            )
        title = getattr(a, "title", None)
        if title:
            _add_item(
                category="name",
                label="HTTP Page Title",
                value=str(title),
                location=host_val,
                tool_source=src,
                asset_id=a_id,
            )
        for tech in getattr(a, "technologies", None) or []:
            t_str = str(tech)
            if t_str.startswith("port:"):
                continue
            _add_item(
                category="name",
                label="Technology / Version",
                value=t_str,
                location=host_val,
                tool_source=src,
                asset_id=a_id,
            )
        for prec in _port_records_from_asset(a):
            port_disp = f"{prec['port']}/{prec['proto']}" + (f" {prec['service']}" if prec["service"] else "") + (f" ({prec['banner']})" if prec["banner"] else "")
            open_ports.append({"asset_id": a_id, "host": host_val, "ip_address": ip_addr, **prec})
            _add_item(
                category="number",
                label="Open Port / Service",
                value=port_disp.strip(),
                location=ip_addr or host_val,
                tool_source=src,
                asset_id=a_id,
            )

    # 3. Findings: extracted flags, keys, credentials, IDs, names, internal IPs, plus Finding IDs
    for f in findings:
        f_id = str(getattr(f, "id", "") or "")
        f_url = str(getattr(f, "target_url", "") or "")
        f_tool = str(getattr(f, "tool_source", "") or "aegispt")
        ev = getattr(f, "evidence", None) or {}
        if isinstance(ev, dict):
            extracted = ev.get("extracted_intel")
            if isinstance(extracted, list):
                for entry in extracted:
                    if not isinstance(entry, dict) or not entry.get("value"):
                        continue
                    _add_item(
                        category=str(entry.get("category") or "key"),
                        label=str(entry.get("label") or "Extracted Secret"),
                        value=str(entry["value"]),
                        masked_value=str(entry.get("masked_value")) if entry.get("masked_value") is not None else None,
                        sensitive=bool(entry.get("sensitive", False)),
                        location=str(entry.get("location") or f_url),
                        tool_source=str(entry.get("tool_source") or f_tool),
                        finding_id=f_id,
                    )
            elif ev.get("raw_value"):
                _add_item(
                    category="key",
                    label=str(ev.get("detector") or ev.get("rule_id") or ev.get("secret_type") or f.title),
                    value=str(ev["raw_value"]),
                    masked_value=str(ev.get("masked_sample") or mask_value(str(ev["raw_value"]))),
                    sensitive=True,
                    location=str(ev.get("artifact") or f_url),
                    tool_source=f_tool,
                    finding_id=f_id,
                )

    # 4. ToolRuns: also gather full extracted_intel persisted on ToolRun.summary
    for r in runs:
        summary = getattr(r, "summary", None) or {}
        if not isinstance(summary, dict):
            continue
        r_tool = str(getattr(r, "tool_name", "") or "tool")
        r_target = str(getattr(r, "target", "") or "")
        extracted_run = summary.get("extracted_intel")
        if isinstance(extracted_run, list):
            for entry in extracted_run:
                if not isinstance(entry, dict) or not entry.get("value"):
                    continue
                _add_item(
                    category=str(entry.get("category") or "key"),
                    label=str(entry.get("label") or "Extracted Secret"),
                    value=str(entry["value"]),
                    masked_value=str(entry.get("masked_value")) if entry.get("masked_value") is not None else None,
                    sensitive=bool(entry.get("sensitive", False)),
                    location=str(entry.get("location") or r_target),
                    tool_source=str(entry.get("tool_source") or r_tool),
                )

    counts = {
        "total": len(items),
        "flag": sum(1 for i in items if i["category"] == "flag"),
        "key": sum(1 for i in items if i["category"] == "key"),
        "credential": sum(1 for i in items if i["category"] == "credential"),
        "identifier": sum(1 for i in items if i["category"] == "identifier"),
        "name": sum(1 for i in items if i["category"] == "name"),
        "number": sum(1 for i in items if i["category"] == "number"),
        "open_ports": len(open_ports),
    }
    return {
        "items": items,
        "counts": counts,
        "open_ports": open_ports,
    }

"""Scan snapshot capture & delta diff computation for engagement comparisons."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, Endpoint, Finding, ScanSnapshot


async def capture_snapshot(
    session: AsyncSession, engagement_id: str, label: str = "snapshot"
) -> ScanSnapshot:
    assets = (
        await session.execute(select(Asset).where(Asset.engagement_id == engagement_id))
    ).scalars().all()
    endpoints = (
        await session.execute(select(Endpoint).where(Endpoint.engagement_id == engagement_id))
    ).scalars().all()
    findings = (
        await session.execute(select(Finding).where(Finding.engagement_id == engagement_id))
    ).scalars().all()

    asset_keys = sorted(f"{a.asset_type}:{a.value}" for a in assets)
    endpoint_keys = sorted(f"{e.method} {e.url}" for e in endpoints)
    finding_fps = sorted(
        f"{f.severity}|{f.title}|{f.target_url}|{f.fingerprint}"
        for f in findings
        if f.status != "false_positive"
    )
    open_ports = sorted(
        {
            f"{a.value} -> {t}"
            for a in assets
            for t in (a.technologies or [])
            if t.startswith("port:")
        }
    )

    snap = ScanSnapshot(
        engagement_id=engagement_id,
        label=label,
        assets_count=len(assets),
        endpoints_count=len(endpoints),
        findings_count=len(finding_fps),
        asset_keys=asset_keys,
        endpoint_keys=endpoint_keys,
        finding_fingerprints=finding_fps,
        open_ports=open_ports,
    )
    session.add(snap)
    await session.flush()
    return snap


def compute_snapshot_diff(base: ScanSnapshot, target: ScanSnapshot) -> dict[str, Any]:
    base_assets = set(base.asset_keys or [])
    tgt_assets = set(target.asset_keys or [])
    base_eps = set(base.endpoint_keys or [])
    tgt_eps = set(target.endpoint_keys or [])
    base_finds = set(base.finding_fingerprints or [])
    tgt_finds = set(target.finding_fingerprints or [])
    base_ports = set(base.open_ports or [])
    tgt_ports = set(target.open_ports or [])

    return {
        "baseline": {
            "id": base.id,
            "label": base.label,
            "created_at": base.created_at.isoformat() if base.created_at else None,
        },
        "current": {
            "id": target.id,
            "label": target.label,
            "created_at": target.created_at.isoformat() if target.created_at else None,
        },
        "new_assets": sorted(tgt_assets - base_assets),
        "removed_assets": sorted(base_assets - tgt_assets),
        "new_endpoints": sorted(tgt_eps - base_eps),
        "new_findings": sorted(tgt_finds - base_finds),
        "resolved_findings": sorted(base_finds - tgt_finds),
        "new_open_ports": sorted(tgt_ports - base_ports),
    }

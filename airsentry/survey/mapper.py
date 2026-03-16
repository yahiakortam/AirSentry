"""Generate an interactive HTML map from saved survey scans using folium."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from airsentry.survey.store import ScanRecord


def generate_map(
    records: list[ScanRecord],
    output_path: Optional[Path] = None,
) -> Path:
    """
    Generate an HTML map with colored markers for each survey location.

    Markers:
    - Green  = risk score <= 30
    - Orange = risk score 31-60
    - Red    = risk score > 60

    Clicking a marker shows the location summary.

    Returns the path to the generated HTML file.
    """
    try:
        import folium
    except ImportError:
        raise ImportError(
            "folium is required for map generation.\n\n"
            "Install it with:  pip install folium"
        )

    if output_path is None:
        output_path = Path.home() / ".airsentry" / "survey_map.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Filter records that have coordinates
    geo_records = [r for r in records if r.latitude is not None and r.longitude is not None]

    if not geo_records:
        # Generate a placeholder map centered on 0,0
        m = folium.Map(location=[0, 0], zoom_start=2, tiles="CartoDB dark_matter")
        m.save(str(output_path))
        return output_path

    # Center the map on the average of all coordinates
    avg_lat = sum(r.latitude for r in geo_records) / len(geo_records)
    avg_lon = sum(r.longitude for r in geo_records) / len(geo_records)

    m = folium.Map(
        location=[avg_lat, avg_lon],
        zoom_start=13,
        tiles="CartoDB dark_matter",
    )

    for record in geo_records:
        score = record.result.risk_score
        if score <= 30:
            color = "green"
            icon_color = "darkgreen"
        elif score <= 60:
            color = "orange"
            icon_color = "orange"
        else:
            color = "red"
            icon_color = "darkred"

        popup_html = (
            f"<div style='font-family: sans-serif; min-width: 200px;'>"
            f"<h4 style='margin: 0 0 8px 0;'>{record.location_name}</h4>"
            f"<table style='font-size: 12px; border-collapse: collapse;'>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>Risk Score</td>"
            f"<td style='font-weight: 700; color: {color};'>{score}/100 ({record.result.risk_label})</td></tr>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>Networks</td>"
            f"<td>{record.result.total_networks}</td></tr>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>Open</td>"
            f"<td>{record.result.open_count}</td></tr>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>WPA2</td>"
            f"<td>{record.result.wpa2_count}</td></tr>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>WPA3</td>"
            f"<td>{record.result.wpa3_count}</td></tr>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>Duplicates</td>"
            f"<td>{record.result.duplicate_ssid_count}</td></tr>"
            f"<tr><td style='padding: 2px 8px 2px 0; color: #888;'>Scanned</td>"
            f"<td>{record.timestamp[:19]}</td></tr>"
            f"</table>"
            f"</div>"
        )

        folium.Marker(
            location=[record.latitude, record.longitude],
            popup=folium.Popup(popup_html, max_width=280),
            tooltip=f"{record.location_name} — {score}/100",
            icon=folium.Icon(color=color, icon_color="white", icon="wifi", prefix="fa"),
        ).add_to(m)

    m.save(str(output_path))
    return output_path

import hashlib
import json
from datetime import datetime

from fpdf import FPDF


def generate_eu_ai_act_pdf(tenant_id=None):
    from src.nist_attestation import generate_attestation_data, FEATURE_NIST_MAP
    from src.eu_ai_act_mapping import (
        EU_AI_ACT_ARTICLES,
        FEATURE_EU_MAP,
        get_eu_coverage_by_article,
    )

    data = generate_attestation_data(tenant_id)
    summary = data["summary"]
    live = data["live_data"]
    integrity = data["integrity"]
    meta = data["metadata"]
    now = datetime.utcnow()

    eu_coverage = get_eu_coverage_by_article()

    articles_with_features = sum(1 for v in eu_coverage.values() if v["feature_count"] > 0)
    total_articles = len(EU_AI_ACT_ARTICLES)
    eu_score = round((articles_with_features / total_articles) * 100, 1) if total_articles > 0 else 0

    feature_eu_lookup = {}
    for fm in FEATURE_EU_MAP:
        feature_eu_lookup[fm["number"]] = fm

    features_with_hashes = []
    for feature in data["features"]:
        eu_info = feature_eu_lookup.get(feature["number"], {})
        eu_articles = eu_info.get("eu_articles", [])
        eu_evidence = eu_info.get("evidence", "")
        hash_input = json.dumps({
            "feature_number": feature["number"],
            "feature_name": feature["name"],
            "eu_articles": eu_articles,
            "component": feature.get("component", ""),
            "evidence": eu_evidence,
            "tenant_id": tenant_id or "global",
        }, sort_keys=True)
        eu_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        features_with_hashes.append({
            **feature,
            "eu_articles": eu_articles,
            "eu_evidence": eu_evidence,
            "eu_hash": eu_hash,
        })

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    pdf.add_page()
    pdf.set_fill_color(20, 20, 30)
    pdf.rect(0, 0, 210, 55, 'F')
    pdf.set_text_color(255, 140, 0)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_y(10)
    pdf.cell(0, 10, "SNAPWIRE", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(220, 220, 230)
    pdf.cell(0, 7, "EU AI Act Conformity Assessment", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(180, 180, 190)
    pdf.cell(0, 6, "Agentic Runtime Security (ARS) Platform - Feature-to-Article Mapping", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(150, 150, 160)
    pdf.cell(0, 6, f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(63)
    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1. Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    score_color = (0, 180, 150) if eu_score >= 80 else (220, 170, 50) if eu_score >= 50 else (220, 60, 80)

    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(*score_color)
    pdf.cell(50, 20, f"{eu_score:.0f}%", new_x="RIGHT", new_y="TOP")

    x_pos = pdf.get_x() + 5
    y_pos = pdf.get_y()
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(60, 60, 70)
    pdf.set_xy(x_pos, y_pos + 2)
    pdf.cell(0, 6, "EU AI Act Article Coverage Score", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x_pos)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, f"{summary['total_features']} features mapped | {articles_with_features}/{total_articles} articles covered", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    pdf.set_fill_color(245, 245, 250)
    info_items = [
        ("Framework", "EU Artificial Intelligence Act (Regulation 2024/1689)"),
        ("Assessment Type", "Feature-to-Article Conformity Mapping"),
        ("Tenant", meta.get("tenant_id", "global")),
        ("Active Rules", str(live["active_rules_count"])),
        ("Audit Log Events", str(live["audit_log_stats"]["total"])),
        ("Tool Catalog Entries", str(live["tool_catalog_entries"])),
        ("AIBOM Components", str(live["aibom_component_count"])),
    ]
    for label, value in info_items:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(45, 7, f"  {label}:", border=0, fill=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 7, f" {value}", border=0, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "2. Coverage by EU AI Act Article", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_fill_color(240, 240, 245)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(60, 60, 70)
    pdf.cell(25, 8, "Article", border=1, fill=True)
    pdf.cell(50, 8, "Name", border=1, fill=True)
    pdf.cell(55, 8, "Description", border=1, fill=True)
    pdf.cell(20, 8, "Features", border=1, fill=True)
    pdf.cell(20, 8, "Coverage", border=1, fill=True)
    pdf.cell(20, 8, "Status", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8)
    article_order = ["ART-9", "ART-10", "ART-11", "ART-12", "ART-13", "ART-14", "ART-15", "ART-17", "ART-26", "ART-72"]
    for art_id in article_order:
        cov = eu_coverage.get(art_id, {})
        count = cov.get("feature_count", 0)
        pct = cov.get("coverage_percentage", 0)

        if count > 0:
            status_color = (16, 185, 129)
            status_label = "Active"
        else:
            status_color = (220, 60, 80)
            status_label = "Gap"

        art_info = EU_AI_ACT_ARTICLES.get(art_id, {})
        pdf.set_text_color(40, 40, 50)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(25, 7, f"  {art_info.get('article', art_id)}", border=1)
        pdf.set_font("Helvetica", "", 7)
        name = art_info.get("name", "")
        if len(name) > 30:
            name = name[:27] + "..."
        pdf.cell(50, 7, f" {name}", border=1)
        desc = cov.get("description", art_info.get("description", ""))
        if len(desc) > 35:
            desc = desc[:32] + "..."
        pdf.cell(55, 7, f" {desc}", border=1)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(20, 7, f"  {count}", border=1)
        pdf.cell(20, 7, f"  {pct:.1f}%", border=1)
        pdf.set_text_color(*status_color)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(20, 7, f"  {status_label}", border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "3. Feature-to-Article Mapping", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 110)
    pdf.multi_cell(0, 5, "Each feature below is mapped to one or more EU AI Act articles with a SHA-256 hash of the enforcement evidence. Hashes incorporate tenant configuration state for independent verification.")
    pdf.ln(3)

    for feature in features_with_hashes:
        if pdf.get_y() > 245:
            pdf.add_page()

        pdf.set_fill_color(35, 35, 50)
        pdf.set_text_color(255, 140, 0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, f"  Feature #{feature['number']}: {feature['name']}", fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_fill_color(248, 248, 252)
        pdf.set_text_color(60, 60, 70)
        pdf.set_font("Helvetica", "", 8)
        desc = feature.get("description", "")
        pdf.multi_cell(0, 4.5, f"  {desc}", fill=True)

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(80, 80, 90)
        article_labels = []
        for art_id in feature.get("eu_articles", []):
            art_info = EU_AI_ACT_ARTICLES.get(art_id, {})
            article_labels.append(f"{art_info.get('article', art_id)} ({art_info.get('name', '')})")
        articles_str = ", ".join(article_labels) if article_labels else "N/A"
        pdf.cell(30, 5, "  EU AI Act:", fill=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(0, 100, 160)
        if len(articles_str) > 90:
            articles_str = articles_str[:87] + "..."
        pdf.cell(0, 5, f" {articles_str}", fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(80, 80, 90)
        pdf.cell(30, 5, "  Component:", fill=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(60, 60, 70)
        pdf.cell(0, 5, f" {feature.get('component', 'N/A')}", fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(80, 80, 90)
        pdf.cell(30, 5, "  Evidence:", fill=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(60, 60, 70)
        evidence = feature.get("eu_evidence", feature.get("evidence", ""))
        if len(evidence) > 100:
            evidence = evidence[:97] + "..."
        pdf.cell(0, 5, f" {evidence}", fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Courier", "", 6)
        pdf.set_text_color(120, 120, 130)
        sha = feature.get("eu_hash", "N/A")
        pdf.cell(0, 4, f"  SHA-256: {sha}", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.add_page()
    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "4. Audit Log Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    stats = live["audit_log_stats"]
    taint = live["taint_tracking_config"]
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 70)
    stat_items = [
        ("Total Events Audited", str(stats["total"])),
        ("Blocked Actions", str(stats["blocked"])),
        ("Allowed Actions", str(stats["allowed"])),
        ("Held for Review", str(stats["held"])),
        ("Source Tools (Taint)", str(taint["sources"])),
        ("Sink Tools (Taint)", str(taint["sinks"])),
        ("Processor Tools", str(taint["processors"])),
    ]
    pdf.set_fill_color(245, 245, 250)
    for label, value in stat_items:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(55, 7, f"  {label}:", border=0, fill=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 7, f" {value}", border=0, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "5. Integrity Verification", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_fill_color(35, 35, 50)
    pdf.set_text_color(200, 200, 210)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 7, "  Bundle Integrity Hash", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 7)
    pdf.set_text_color(0, 220, 160)
    pdf.cell(0, 6, f"  SHA-256: {integrity['bundle_sha256']}", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(180, 180, 190)
    pdf.cell(0, 6, f"  Generated: {integrity['generated_at']}", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 130)
    pdf.multi_cell(0, 4, "This hash can be independently verified by regenerating the attestation data with the same tenant configuration state and comparing the SHA-256 output.")
    pdf.ln(6)

    pdf.set_text_color(40, 40, 50)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "6. Legal Disclaimer", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(80, 80, 90)
    pdf.multi_cell(0, 5, (
        "This conformity assessment report is generated by Snapwire and is informational only. "
        "It does not constitute a formal EU AI Act conformity assessment, certification, or legal compliance determination. "
        "It reflects feature-to-article mapping based on implemented Snapwire capabilities. "
        "Organizations must perform their own conformity assessments as required by Regulation (EU) 2024/1689. "
        "All blocks, alerts, and signals are heuristic and advisory in nature. "
        "The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator."
    ))
    pdf.ln(3)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 110)
    pdf.multi_cell(0, 4, "Snapwire is a technical monitoring utility. All blocks, alerts, and signals generated are heuristic and advisory in nature. The final Duty of Care for all agent actions and budgetary releases remains solely with the human operator.")
    pdf.ln(4)

    pdf.set_fill_color(20, 20, 30)
    footer_y = max(pdf.get_y(), 270)
    pdf.rect(0, footer_y, 210, 30, 'F')
    pdf.set_y(footer_y + 4)
    pdf.set_text_color(255, 140, 0)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, "SNAPWIRE - Agentic Runtime Security", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(150, 150, 160)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5, f"EU AI Act Conformity Assessment | {now.strftime('%Y-%m-%d')} | Apache 2.0 License", align="C", new_x="LMARGIN", new_y="NEXT")

    return pdf.output()

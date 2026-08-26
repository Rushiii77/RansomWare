"""
reporting/report_generator.py

Phase 15: PDF Incident Forensic Report Generator.

Uses ReportLab to generate formal, professional cybersecurity incident reports
and forensic audit summaries.
"""

import os
import platform
import socket
import time
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import config
from database.db_manager import DatabaseManager, IncidentRecord
from utils.logger import get_logger

logger = get_logger("report_generator")

REPORTS_DIR = os.path.join(config.BASE_DIR, "reporting", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:
    """Generates PDF forensic reports for detected incidents and system security audits."""

    def __init__(self, output_dir: str = REPORTS_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self):
        self.title_style = ParagraphStyle(
            "ReportTitle",
            parent=self.styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1a73e8"),
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        self.subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=self.styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#5f6368"),
            spaceAfter=12,
            fontName="Helvetica",
        )
        self.section_heading = ParagraphStyle(
            "SectionHeading",
            parent=self.styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#202124"),
            spaceBefore=10,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        self.body_style = ParagraphStyle(
            "ReportBody",
            parent=self.styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#3c4043"),
            fontName="Helvetica",
        )
        self.table_header_style = ParagraphStyle(
            "TableHeader",
            parent=self.styles["Normal"],
            fontSize=9,
            leading=11,
            textColor=colors.white,
            fontName="Helvetica-Bold",
        )
        self.table_cell_style = ParagraphStyle(
            "TableCell",
            parent=self.styles["Normal"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#202124"),
            fontName="Helvetica",
        )

    def generate_incident_report(
        self,
        incident: IncidentRecord,
        filename: Optional[str] = None,
    ) -> str:
        """Generate a single-incident detailed forensic report PDF."""
        if not filename:
            filename = f"incident_report_{incident.id}_{int(incident.timestamp)}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        story = []

        # -------------------------------------------------------------------
        # Header Banner
        # -------------------------------------------------------------------
        story.append(Paragraph("AI-BASED RANSOMWARE DETECTION SYSTEM", self.title_style))
        story.append(Paragraph(f"Forensic Incident Investigation Report — Case #INC-{incident.id:04d}", self.subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a73e8"), spaceAfter=12))

        # -------------------------------------------------------------------
        # 1. System & Case Metadata
        # -------------------------------------------------------------------
        story.append(Paragraph("1. Incident Overview & Target System", self.section_heading))

        is_crit = incident.threat_level in ("CRITICAL", "HIGH_RISK")
        badge_color = "#d93025" if is_crit else "#e37400"
        score_val = int(incident.confidence * 100)

        meta_data = [
            [
                Paragraph("<b>Incident Case ID:</b>", self.table_cell_style),
                Paragraph(f"INC-{incident.id:04d}", self.table_cell_style),
                Paragraph("<b>Detected Threat Level:</b>", self.table_cell_style),
                Paragraph(f"<font color='{badge_color}'><b>{incident.threat_level}</b></font>", self.table_cell_style),
            ],
            [
                Paragraph("<b>Timestamp:</b>", self.table_cell_style),
                Paragraph(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(incident.timestamp)), self.table_cell_style),
                Paragraph("<b>AI Risk Score:</b>", self.table_cell_style),
                Paragraph(f"<b>{score_val}/100</b> (Probability: {incident.confidence*100:.1f}%)", self.table_cell_style),
            ],
            [
                Paragraph("<b>Target Hostname:</b>", self.table_cell_style),
                Paragraph(socket.gethostname(), self.table_cell_style),
                Paragraph("<b>Operating System:</b>", self.table_cell_style),
                Paragraph(f"{platform.system()} {platform.release()}", self.table_cell_style),
            ],
        ]

        meta_table = Table(meta_data, colWidths=[1.6 * inch, 2.0 * inch, 1.6 * inch, 2.0 * inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dadce0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8eaed")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------------
        # 2. Offending Process Information
        # -------------------------------------------------------------------
        story.append(Paragraph("2. Offending Process Attribution", self.section_heading))

        proc_data = [
            [
                Paragraph("<b>Process Name:</b>", self.table_cell_style),
                Paragraph(f"<font color='#d93025'><b>{incident.suspect_name or 'Unknown'}</b></font>", self.table_cell_style),
            ],
            [
                Paragraph("<b>Process ID (PID):</b>", self.table_cell_style),
                Paragraph(str(incident.suspect_pid or "N/A"), self.table_cell_style),
            ],
            [
                Paragraph("<b>Automated Action Taken:</b>", self.table_cell_style),
                Paragraph(f"<b>{incident.action_taken}</b>", self.table_cell_style),
            ],
            [
                Paragraph("<b>Technical Action Details:</b>", self.table_cell_style),
                Paragraph(incident.details or "N/A", self.table_cell_style),
            ],
        ]

        proc_table = Table(proc_data, colWidths=[2.2 * inch, 5.0 * inch])
        proc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef7e0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dadce0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8eaed")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(proc_table)
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------------
        # 3. Behavioral Features & Signatures
        # -------------------------------------------------------------------
        story.append(Paragraph("3. Behavioral Features & Telemetry Signatures (10s Window)", self.section_heading))

        feat = incident.features or {}
        feat_data = [
            [
                Paragraph("Behavioral Feature Metric", self.table_header_style),
                Paragraph("Observed Value", self.table_header_style),
                Paragraph("Baseline Reference", self.table_header_style),
                Paragraph("Threat Indicator Rationale", self.table_header_style),
            ],
            [
                Paragraph("Total File Operations", self.table_cell_style),
                Paragraph(f"<b>{feat.get('total_operations', 0):.0f}</b> ops", self.table_cell_style),
                Paragraph("0 – 10 ops", self.table_cell_style),
                Paragraph("Unusually high file system activity burst", self.table_cell_style),
            ],
            [
                Paragraph("Operation Rate", self.table_cell_style),
                Paragraph(f"<b>{feat.get('operation_rate_per_sec', 0.0):.2f}</b> ops/sec", self.table_cell_style),
                Paragraph("< 1.0 ops/sec", self.table_cell_style),
                Paragraph("Rapid batch traversal signature", self.table_cell_style),
            ],
            [
                Paragraph("Files Renamed", self.table_cell_style),
                Paragraph(f"<b>{feat.get('num_renamed', 0):.0f}</b> files", self.table_cell_style),
                Paragraph("0 – 1 files", self.table_cell_style),
                Paragraph("Ransomware extension appending pattern", self.table_cell_style),
            ],
            [
                Paragraph("Rename-to-Modify Ratio", self.table_cell_style),
                Paragraph(f"<b>{feat.get('rename_modify_ratio', 0.0):.2f}</b>", self.table_cell_style),
                Paragraph("< 0.10", self.table_cell_style),
                Paragraph("Strong correlation to encryption rename cycle", self.table_cell_style),
            ],
            [
                Paragraph("Unique Directories Affected", self.table_cell_style),
                Paragraph(f"<b>{feat.get('unique_directories', 0):.0f}</b> dirs", self.table_cell_style),
                Paragraph("1 – 2 dirs", self.table_cell_style),
                Paragraph("Multi-folder traversal and encryption scan", self.table_cell_style),
            ],
            [
                Paragraph("Process CPU Utilization", self.table_cell_style),
                Paragraph(f"<b>{feat.get('cpu_percent', 0.0):.1f}%</b>", self.table_cell_style),
                Paragraph("< 15.0%", self.table_cell_style),
                Paragraph("Computational load during cryptographic loop", self.table_cell_style),
            ],
        ]

        feat_table = Table(feat_data, colWidths=[2.2 * inch, 1.4 * inch, 1.4 * inch, 2.2 * inch])
        feat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a73e8")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dadce0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8eaed")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(feat_table)
        story.append(Spacer(1, 12))

        # -------------------------------------------------------------------
        # 4. Executive Summary & Response Verification
        # -------------------------------------------------------------------
        story.append(Paragraph("4. Incident Resolution & Defensive Assessment", self.section_heading))
        summary_text = (
            f"The AI-Based Ransomware Detection & Process Termination System identified high-confidence "
            f"ransomware behavioral activity originating from PID {incident.suspect_pid or 'N/A'} ({incident.suspect_name or 'unknown'}). "
            f"The observed multi-event signature exhibited an abnormal rename-to-modify ratio ({feat.get('rename_modify_ratio', 0.0):.2f}) "
            f"and high operation rate ({feat.get('operation_rate_per_sec', 0.0):.2f} ops/sec).<br/><br/>"
            f"<b>Action Executed:</b> {incident.action_taken}.<br/>"
            f"<b>Forensic Recommendation:</b> Perform sandbox analysis on binary path, check directory integrity, and verify backup state."
        )
        story.append(Paragraph(summary_text, self.body_style))
        story.append(Spacer(1, 15))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dadce0"), spaceAfter=8))
        footer_text = f"Report Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Defensive Cybersecurity Major Project Prototype"
        story.append(Paragraph(footer_text, ParagraphStyle("Footer", parent=self.body_style, fontSize=7.5, textColor=colors.gray, alignment=1)))

        doc.build(story)
        logger.info("Generated PDF incident report at %s", filepath)
        return filepath

    def generate_security_audit_report(
        self,
        incidents: List[IncidentRecord],
        stats: Dict[str, int],
        filename: Optional[str] = None,
    ) -> str:
        """Generate a complete system security audit summary PDF."""
        if not filename:
            filename = f"security_audit_summary_{int(time.time())}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        story = []

        story.append(Paragraph("AI-BASED RANSOMWARE DETECTION SYSTEM", self.title_style))
        story.append(Paragraph("System Security Audit & Threat Statistics Summary Report", self.subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a73e8"), spaceAfter=12))

        # Stats Cards Table
        stats_data = [
            [
                Paragraph("<b>Total Threats Detected</b>", self.table_header_style),
                Paragraph("<b>Terminated Processes</b>", self.table_header_style),
                Paragraph("<b>Ignored / Allowed</b>", self.table_header_style),
                Paragraph("<b>Protected Baseline</b>", self.table_header_style),
            ],
            [
                Paragraph(f"<font size=14><b>{stats.get('total_threats', 0)}</b></font>", self.table_cell_style),
                Paragraph(f"<font size=14 color='#d93025'><b>{stats.get('terminated', 0)}</b></font>", self.table_cell_style),
                Paragraph(f"<font size=14 color='#5f6368'><b>{stats.get('ignored', 0)}</b></font>", self.table_cell_style),
                Paragraph("<font size=14 color='#1b8738'><b>ACTIVE</b></font>", self.table_cell_style),
            ],
        ]
        stats_table = Table(stats_data, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202124")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8f9fa")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dadce0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8eaed")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 14))

        # Recent Incidents Log
        story.append(Paragraph("Recent Detection Incidents Log", self.section_heading))
        inc_data = [
            [
                Paragraph("ID", self.table_header_style),
                Paragraph("Timestamp", self.table_header_style),
                Paragraph("Threat Level", self.table_header_style),
                Paragraph("Confidence", self.table_header_style),
                Paragraph("Offending Process", self.table_header_style),
                Paragraph("Action Taken", self.table_header_style),
            ]
        ]

        if not incidents:
            inc_data.append([
                Paragraph("—", self.table_cell_style),
                Paragraph("No threat incidents recorded. System clean.", self.table_cell_style),
                Paragraph("—", self.table_cell_style),
                Paragraph("—", self.table_cell_style),
                Paragraph("—", self.table_cell_style),
                Paragraph("—", self.table_cell_style),
            ])
        else:
            for inc in incidents[:25]:
                t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc.timestamp))
                inc_data.append([
                    Paragraph(f"#{inc.id}", self.table_cell_style),
                    Paragraph(t_str, self.table_cell_style),
                    Paragraph(inc.threat_level, self.table_cell_style),
                    Paragraph(f"{inc.confidence*100:.1f}%", self.table_cell_style),
                    Paragraph(f"{inc.suspect_name} (PID {inc.suspect_pid})", self.table_cell_style),
                    Paragraph(inc.action_taken, self.table_cell_style),
                ])

        inc_table = Table(inc_data, colWidths=[0.6 * inch, 1.8 * inch, 1.2 * inch, 1.0 * inch, 1.4 * inch, 1.2 * inch])
        inc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a73e8")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dadce0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e8eaed")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(inc_table)

        doc.build(story)
        logger.info("Generated PDF security audit report at %s", filepath)
        return filepath

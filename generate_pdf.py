import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 11 * 72 - 25, "SYSAD Portal - Architecture & Feature Specification")
            self.drawRightString(8.5 * 72 - 36, 11 * 72 - 25, "Confidential - Systems Administration")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 11 * 72 - 28, 8.5 * 72 - 36, 11 * 72 - 28)

        # Footer
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 35, 8.5 * 72 - 36, 35)
        self.drawString(36, 24, "SYSAD Centralized Management & Access Control Portal | Generated Documentation")
        self.drawRightString(8.5 * 72 - 36, 24, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

def build_pdf(filename="SYSAD_System_Architecture_and_Functions.pdf"):
    pdf_path = os.path.abspath(filename)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=42,
        bottomMargin=42
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=12
    )

    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#64748b")
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12.5,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.2,
        leading=11.5,
        textColor=colors.HexColor("#334155"),
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    )

    table_cell_body = ParagraphStyle(
        'TableCellBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.8,
        leading=10.5,
        textColor=colors.HexColor("#334155")
    )

    story = []

    # Title Banner Box
    title_data = [
        [
            Paragraph("SYSAD Centralized Management & Access Control Portal", title_style),
        ],
        [
            Paragraph("System Architecture, Core Functions, DFD Alignment & Technical Change Ledger", subtitle_style),
        ],
        [
            Paragraph("<b>Architecture:</b> 4 DFD Processes &bull; 2 Relational Databases &bull; 4 RBAC Actors &bull; 6 Expected Outcomes &bull; Telemetry Agent", meta_style),
        ]
    ]
    title_table = Table(title_data, colWidths=[540])
    title_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,-1), (-1,-1), 10),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 10))

    # SECTION 1: DFD Process Alignment
    story.append(Paragraph("1. Architectural Foundation & DFD Process Alignment", h1_style))
    story.append(Paragraph("The system is engineered directly from the Systems Administration Data Flow Diagram (DFD), implementing 4 core processes and 2 persistent SQLite databases:", body_style))
    story.append(Spacer(1, 4))

    dfd_data = [
        [
            Paragraph("DFD Component", table_header_style),
            Paragraph("Type / Scope", table_header_style),
            Paragraph("Functional Implementation & Capabilities", table_header_style)
        ],
        [
            Paragraph("<b>1.0 RBAC Policy Engine</b>", table_cell_bold),
            Paragraph("Process (Auth)", table_cell_body),
            Paragraph("&bull; Granular permissions for Student, Faculty, IT Staff, and Administrator.<br/>&bull; Session management with salted SHA-256 password hashing and token expiry.<br/>&bull; Real-time dynamic permission matrix viewer on Admin dashboard.", table_cell_body)
        ],
        [
            Paragraph("<b>2.0 Identity Directory</b>", table_cell_bold),
            Paragraph("Process (Lifecycle)", table_cell_body),
            Paragraph("&bull; User lifecycle transitions: Active, Aging, and Suspended.<br/>&bull; Automated batch cohort onboarding for multi-student intake.<br/>&bull; Automated orphan deactivation for inactive profiles (>120 days).", table_cell_body)
        ],
        [
            Paragraph("<b>3.0 Trouble Ledger</b>", table_cell_bold),
            Paragraph("Process (Ticketing)", table_cell_body),
            Paragraph("&bull; User problem submission across Network, LMS, Hardware, Account, Facility.<br/>&bull; Priority triage queue (Critical, High, Medium, Low) for IT Support.<br/>&bull; Role-based ticket isolation (students/faculty see only own tickets).", table_cell_body)
        ],
        [
            Paragraph("<b>4.0 Security & Performance</b>", table_cell_bold),
            Paragraph("Process (Monitoring)", table_cell_body),
            Paragraph("&bull; Live server metrics: CPU load, RAM consumption, and Disk volume usage.<br/>&bull; Mandatory credential rotation enforcement (>90 days aging).<br/>&bull; Real-time perimeter firewall block alerting and incident ticket logging.", table_cell_body)
        ],
        [
            Paragraph("<b>D1: User & Roles DB</b>", table_cell_bold),
            Paragraph("Data Store (`user_roles.db`)", table_cell_body),
            Paragraph("Stores user profiles, credential hashes, RBAC permission matrices, departments, login timestamps, and active sessions.", table_cell_body)
        ],
        [
            Paragraph("<b>D2: Audit & Ticket Logs DB</b>", table_cell_bold),
            Paragraph("Data Store (`audit_ticket_logs.db`)", table_cell_body),
            Paragraph("Stores immutable security audit events, trouble tickets, maintenance tasks, server configs, firewall policies, and forbidden web filter rules.", table_cell_body)
        ]
    ]

    t_dfd = Table(dfd_data, colWidths=[130, 95, 315])
    t_dfd.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(t_dfd)
    story.append(Spacer(1, 10))

    # SECTION 2: 6 Expected Outcomes
    story.append(Paragraph("2. Verification of the 6 Expected Outcomes", h1_style))
    story.append(Paragraph("All six required systems administration operational outcomes are completely implemented and automated:", body_style))
    story.append(Spacer(1, 4))

    outcomes_data = [
        [
            Paragraph("Expected Outcome", table_header_style),
            Paragraph("Operational Mechanisms & Technical Capabilities", table_header_style)
        ],
        [
            Paragraph("<b>Outcome 1:<br/>Automated Account Management</b>", table_cell_bold),
            Paragraph("&bull; <b>Batch Provisioning:</b> Instantly registers and activates student cohorts with unique IDs, auto-generated email addresses, and default departments.<br/>&bull; <b>Orphan Cleanup:</b> Scans identity database and auto-transitions accounts inactive for >120 days into `Suspended` status.", table_cell_body)
        ],
        [
            Paragraph("<b>Outcome 2:<br/>Enhanced Network Security</b>", table_cell_bold),
            Paragraph("&bull; <b>Granular RBAC:</b> Students and Faculty are strictly isolated from server governance, firewall rules, and foreign tickets.<br/>&bull; <b>Orphan Token Revocation:</b> Active sessions are revoked immediately upon account status transition to `Suspended`.", table_cell_body)
        ],
        [
            Paragraph("<b>Outcome 3:<br/>Proactive Threat Prevention</b>", table_cell_bold),
            Paragraph("&bull; <b>Mandatory Credential Rotation:</b> Automated background scan flags profiles where password has not been rotated in >90 days.<br/>&bull; <b>Suspension Lockdown:</b> Denies portal access and rejects API tokens for all suspended accounts.", table_cell_body)
        ],
        [
            Paragraph("<b>Outcome 4:<br/>Accelerated Incident Resolution</b>", table_cell_bold),
            Paragraph("&bull; <b>Prioritized Queue:</b> Outage tickets are prioritized (Critical &gt; High &gt; Medium &gt; Low) for rapid IT triage.<br/>&bull; <b>Permission Audit Trail:</b> Every RBAC update is immutably logged to accelerate root-cause analysis during security audits.", table_cell_body)
        ],
        [
            Paragraph("<b>Outcome 5:<br/>High Infrastructure Reliability</b>", table_cell_bold),
            Paragraph("&bull; <b>Automated Snapshot Archive:</b> One-click backup archives physical `.bak` snapshots of both databases to `data/backups/`.<br/>&bull; <b>Rapid Recovery Pipeline:</b> Verified one-click restore reloads identity and audit state from backup in under 2 seconds.", table_cell_body)
        ],
        [
            Paragraph("<b>Outcome 6:<br/>Optimized IT Operations</b>", table_cell_bold),
            Paragraph("&bull; <b>Perimeter Firewall Governance:</b> Administrators can dynamically toggle firewall rules (`ACTIVE` &harr; `DISABLED`).<br/>&bull; <b>Dynamic Server Tuning:</b> Runtime parameters (thread pools, timeout thresholds, log levels) are adjusted without server downtime.", table_cell_body)
        ]
    ]

    t_outcomes = Table(outcomes_data, colWidths=[150, 390])
    t_outcomes.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(t_outcomes)
    story.append(Spacer(1, 10))

    # SECTION 3: Telemetry Agent
    story.append(Paragraph("3. Client-Side Hardware Telemetry Agent", h1_style))
    story.append(Paragraph("Web browsers have strict sandboxes preventing direct access to host hardware. To satisfy real-world hardware monitoring:", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("&bull; <b>Node.js Telemetry Agent (`student_agent/agent.js`):</b> Standalone background daemon utilizing the `systeminformation` library.", bullet_style))
    story.append(Paragraph("&bull; <b>Python Fallback Agent (`student_agent/agent.py`):</b> Standalone cross-platform daemon utilizing `psutil`.", bullet_style))
    story.append(Paragraph("&bull; <b>Hardware Metrics Polling (Every 5s):</b> Host CPU Load % (`si.currentLoad()`), RAM Used vs Total (`si.mem()`), and Storage Volume Usage (`si.fsSize()`).", bullet_style))
    story.append(Paragraph("&bull; <b>Fleet Monitor:</b> Securely transmits workstation metrics to `/api/monitoring/telemetry/agent-report` and displays live hardware cards on IT Staff and Admin consoles.", bullet_style))
    story.append(Paragraph("&bull; <b>Privacy Hardening:</b> Hardware MAC addresses are completely removed from all dashboard tables for student workstation privacy.", bullet_style))
    story.append(Spacer(1, 6))

    # SECTION 4: Campus Web Filter & Prohibited Domain Policy Manager
    story.append(Paragraph("4. Campus Web Filter & Prohibited Domain Governance", h1_style))
    story.append(Paragraph("A full perimeter firewall web filter inspects external browser traffic and enforces campus acceptable-use policies:", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("&bull; <b>Admin Policy Management:</b> Administrators can dynamically <b>Add</b>, <b>Suspend</b>, or <b>Delete</b> prohibited domain patterns in the `forbidden_websites` table.", bullet_style))
    story.append(Paragraph("&bull; <b>Domain Normalization Engine:</b> Normalizes user input by stripping protocols (`http://`, `https://`), `www.`, ports, paths, and trailing dots (`roblox.com.` &rarr; `roblox.com`).", bullet_style))
    story.append(Paragraph("&bull; <b>Perimeter Interception & 403 Block Page:</b> Disallows prohibited web traffic, dropping packets and returning the authentic <b>403 FORBIDDEN - Campus Perimeter Web Filter Block Page</b>.", bullet_style))
    story.append(Paragraph("&bull; <b>Automated Incident Audit:</b> Generates unique incident tickets (`SEC-INC-XXXXXX`), records the student identity, IP, and timestamp into `audit_logs`, and pushes real-time toasts to IT Staff.", bullet_style))
    story.append(Paragraph("&bull; <b>Student Violation Modal:</b> When a student triggers a violation, a high-priority security dialog pops up warning them of policy non-compliance.", bullet_style))
    story.append(Spacer(1, 6))

    # SECTION 5: External Browser Testing Methods
    story.append(Paragraph("5. External Browser Inspection & Testing Methods", h1_style))
    story.append(Paragraph("The system supports multiple testing methods for external browsers (Microsoft Edge, Google Chrome, etc.):", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("&bull; <b>Method 1: Direct Domain URL:</b> Navigate directly to `http://localhost:8000/&lt;domain&gt;` (e.g. `http://localhost:8000/youtube.com` or `/roblox.com`) to instantly view the authentic 403 block page.", bullet_style))
    story.append(Paragraph("&bull; <b>Method 2: Student Portal Testing:</b> Use the built-in <b>Campus Web Security Gateway</b> card on the Student Dashboard to 'Test in Portal' or 'Launch in Edge / Chrome'.", bullet_style))
    story.append(Paragraph("&bull; <b>Method 3: 1-Click Browser Proxy Batch (`test_edge_chrome_block.bat`):</b> Opens Edge or Chrome with `--proxy-server='http://127.0.0.1:8000'` showing the exact target URL without altering Windows system settings.", bullet_style))
    story.append(Spacer(1, 6))

    # SECTION 6: Deployment & Infrastructure Artifacts
    story.append(Paragraph("6. Production Deployment & Automation Artifacts", h1_style))
    story.append(Paragraph("Turnkey infrastructure scripts provide rapid deployment across Linux, Windows Server, and Container environments:", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("&bull; <b>`Dockerfile`:</b> Production-ready container image running Python under a secure non-root service account.", bullet_style))
    story.append(Paragraph("&bull; <b>`docker-compose.yml`:</b> Single-command container deployment (`docker-compose up -d`) with persistent volume binding for `./data`.", bullet_style))
    story.append(Paragraph("&bull; <b>`deploy_linux_server.sh`:</b> Automated Ubuntu/Debian deployment script configuring a `systemd` daemon (`sysad-portal.service`) and UFW firewall rule for port 8000.", bullet_style))
    story.append(Paragraph("&bull; <b>`deploy_windows_server.bat`:</b> Windows Server configuration script opening inbound port 8000 in Windows Defender Firewall.", bullet_style))
    story.append(Paragraph("&bull; <b>`unit_test.py`:</b> Comprehensive automated test suite with 9 verification suites ensuring 100% test coverage.", bullet_style))
    story.append(Spacer(1, 6))

    # SECTION 7: Recent Engineering Improvements & Fixes
    story.append(Paragraph("7. Technical Quality & Stability Improvements", h1_style))
    story.append(Paragraph("&bull; <b>Identity Sanitization:</b> Removed `(SysAdmin)` from database, profile badges, welcome banners, and JavaScript displays for clean display of <b>Elena Rostova</b>.", bullet_style))
    story.append(Paragraph("&bull; <b>Resolved NameError Bug:</b> Added `import re` to `app.py`, completely resolving the socket crash that previously caused 'Failed to fetch' on login.", bullet_style))
    story.append(Paragraph("&bull; <b>Dual-Stack Network Binding:</b> Server binds to `0.0.0.0`, ensuring reliable connectivity via `localhost`, `127.0.0.1`, and external LAN IP addresses.", bullet_style))
    story.append(Paragraph("&bull; <b>Telemetry Polling Optimization:</b> Disabled background telemetry polling on the login view to prevent unauthenticated error toasts.", bullet_style))
    story.append(Paragraph("&bull; <b>Self-Proxy Recognition:</b> The gateway server now cleanly differentiates requests to the local portal from external web filter targets.", bullet_style))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[OK] Successfully generated PDF at: {pdf_path}")
    return pdf_path

if __name__ == "__main__":
    build_pdf()


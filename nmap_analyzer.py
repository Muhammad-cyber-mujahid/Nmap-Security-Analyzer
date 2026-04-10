import typer
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import xml.etree.ElementTree as ET
from jinja2 import Template
from defusedxml.ElementTree import parse as safe_parse
import asyncio
from playwright.async_api import async_playwright

# Import from your risky_ports file
from risky_ports import get_risk_level, calculate_host_risk_score

app = typer.Typer(help="Nmap Scan Analyzer & Risk Reporter")
console = Console()

# ...

# ====================== PARSING FUNCTIONS ======================

def parse_nmap_xml(xml_file: Path):
    """Parse Nmap XML output"""
    tree = safe_parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue

        ip = host.find("address").get("addr")
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None and len(hostnames) > 0:
            hostname = hostnames[0].get("name", "")

        ports = []
        for port in host.findall(".//port"):
            if port.find("state").get("state") == "open":
                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                version = ""
                if service is not None:
                    product = service.get("product", "")
                    version_str = service.get("version", "")
                    version = f"{product} {version_str}".strip()

                ports.append({
                    "port": port.get("portid"),
                    "service": service_name,
                    "version": version
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "ports": ports
        })
    return hosts


def parse_nmap_grepable(grep_file: Path):
    """Parse Nmap grepable output (-oG)"""
    hosts = []
    with open(grep_file, 'r') as f:
        for line in f:
            if "Ports:" not in line:
                continue
            parts = line.strip().split()
            ip = parts[1]
            ports = []

            # Extract open ports
            port_info = line.split("Ports: ")[1]
            for p in port_info.split(","):
                if "/open/" in p:
                    port_num = p.split("/")[0].strip()
                    service = p.split("/")[2] if len(p.split("/")) > 2 else "unknown"
                    ports.append({"port": port_num, "service": service, "version": ""})

            hosts.append({
                "ip": ip,
                "hostname": "",
                "ports": ports
            })
    return hosts


# END OF PARSING FUNCTIONS

@app.command()
# ====================== MAIN FUNCTION ======================
def analyze(
        file: Path = typer.Option(None, "--file", "-f", help="Nmap XML or grepable file"),
        severity: str = typer.Option("Medium", "--severity", "-s", help="Minimum severity"),
        output: str = typer.Option("nmap_report", "--output", "-o", help="Report filename prefix"),
        demo: bool = typer.Option(False, "--demo", help="Use realistic compromised scan data"),
):
    """Analyze Nmap scan and generate risk reports"""

    console.print(f"[bold green]🔍 Starting Analysis...[/bold green]")

    with Progress() as progress:
        task = progress.add_task("Parsing scan...", total=1)

        if demo:
            hosts = get_demo_scan_data()
            console.print("[bold yellow]🧪 DEMO MODE Activated - Showing realistic risky scan[/bold yellow]")
        elif file is None:
            console.print("[bold red]Error: Please use --file or --demo[/bold red]")
            raise typer.Exit(1)
        elif file.suffix.lower() == ".xml":
            hosts = parse_nmap_xml(file)
        else:
            hosts = parse_nmap_grepable(file)

        progress.update(task, advance=1)

    # Rest of your code remains the same (risk scoring, table, reports, etc.)
    # Add risk scoring
    severity_levels = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    min_level = severity_levels.get(severity, 1)

    enriched_hosts = []
    for host in hosts:
        for p in host["ports"]:
            risk_info = get_risk_level(p["port"], p["service"], p.get("version", ""))
            p.update(risk_info)

        host_score = calculate_host_risk_score(host["ports"])
        risky_ports = [p for p in host["ports"] if severity_levels.get(p["risk"], 0) >= min_level]

        if risky_ports or host_score > 30:  # Show hosts with some risk
            enriched_hosts.append({
                "ip": host["ip"],
                "hostname": host.get("hostname", ""),
                "risky_ports": risky_ports,
                "total_open": len(host["ports"]),
                "risk_score": host_score,
                "highest_risk": max((p["risk"] for p in risky_ports), default="Low")
            })

    # Terminal Summary in Tabular form
    table = Table(title=" Risk Analysis Summary")
    table.add_column("IP / Host", style="cyan")
    table.add_column("Risk Score", justify="right", style="red")
    table.add_column("Risky Ports", style="yellow")
    table.add_column("Total Open", justify="right")
    table.add_column("Highest Risk")

    for h in sorted(enriched_hosts, key=lambda x: x["risk_score"], reverse=True):
        ports_str = ", ".join(f"{p['port']}" for p in h["risky_ports"][:4])
        table.add_row(h["ip"], str(h["risk_score"]), ports_str, str(h["total_open"]), h["highest_risk"])

    console.print(table)

    # Generate Reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    data = {
        "scan_date": datetime.now().isoformat(),
        "total_hosts": len(hosts),
        "risky_hosts": enriched_hosts,
        "summary": {
            "avg_risk_score": round(sum(h["risk_score"] for h in enriched_hosts) / len(enriched_hosts),
                                    1) if enriched_hosts else 0,
            "critical_hosts": len([h for h in enriched_hosts if h["highest_risk"] == "Critical"])
        }
    }

    # JSON
    json_path = report_dir / f"{output}_{timestamp}.json"
    json_path.write_text(json.dumps(data, indent=2))
    console.print(f"[bold green]✅ JSON saved: {json_path}[/bold green]")

    # Advanced HTML + PDF
    html_path = generate_advanced_html_report(data, report_dir / f"{output}_{timestamp}.html")
    console.print(f"[bold green]📊 Advanced HTML Report: {html_path}[/bold green]")

    pdf_path = asyncio.run(generate_pdf_report(html_path, report_dir / f"{output}_{timestamp}.pdf"))
    console.print(f"[bold green]📕 PDF Report: {pdf_path}[/bold green]")


def generate_advanced_html_report(data, html_path: Path):
    template_str = """
    <!DOCTYPE html>
    <html lang="en" data-theme="dark">
    <head>
        <meta charset="UTF-8">
        <title>Nmap Risk Report - {{ data.scan_date[:10] }}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background:#1e1e1e; color:#eee; margin:40px; }
            table { width:100%; border-collapse:collapse; margin:20px 0; }
            th, td { border:1px solid #444; padding:10px; text-align:left; }
            th { background:#333; cursor:pointer; }
            .critical { color:#ff5555; } .high { color:#ffaa00; }
            .card { background:#2d2d2d; padding:20px; border-radius:8px; margin:15px 0; }
        </style>
    </head>
    <body>
        <h1>🔍 Nmap Security Risk Report</h1>
        <div class="card">
            <h2>Summary</h2>
            <p><strong>Average Risk Score:</strong> {{ data.summary.avg_risk_score }} / 100</p>
            <p><strong>Critical Hosts:</strong> {{ data.summary.critical_hosts }}</p>
        </div>

        <canvas id="riskChart" width="800" height="400"></canvas>

        <table id="riskTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">IP / Host</th>
                    <th onclick="sortTable(1)">Risk Score</th>
                    <th onclick="sortTable(2)">Highest Risk</th>
                    <th onclick="sortTable(3)">Risky Ports</th>
                </tr>
            </thead>
            <tbody>
                {% for host in data.risky_hosts %}
                <tr>
                    <td>{{ host.ip }} {% if host.hostname %}({{ host.hostname }}){% endif %}</td>
                    <td class="{% if host.risk_score >= 70 %}critical{% elif host.risk_score >= 40 %}high{% endif %}">{{ host.risk_score }}</td>
                    <td>{{ host.highest_risk }}</td>
                    <td>
                        {% for p in host.risky_ports[:6] %}
                            <b>{{ p.port }}</b> ({{ p.name }})<br>
                        {% endfor %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <script>
            // Risk Score Distribution Chart
            const ctx = document.getElementById('riskChart');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: {{ data.risky_hosts | map(attribute='ip') | list | tojson }},
                    datasets: [{
                        label: 'Host Risk Score',
                        data: {{ data.risky_hosts | map(attribute='risk_score') | list | tojson }},
                        backgroundColor: '#ff5555'
                    }]
                },
                options: { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } }
            });

            // Simple Sortable Table
            function sortTable(n) {
                let table = document.getElementById("riskTable");
                let rows = Array.from(table.rows).slice(1);
                rows.sort((a, b) => {
                    let x = a.cells[n].textContent.trim();
                    let y = b.cells[n].textContent.trim();
                    return isNaN(x) ? x.localeCompare(y) : parseFloat(x) - parseFloat(y);
                });
                rows.forEach(row => table.tBodies[0].appendChild(row));
            }
        </script>
    </body>
    </html>
    """
    template = Template(template_str)
    html = template.render(data=data)
    html_path.write_text(html)
    return html_path


async def generate_pdf_report(html_path: Path, pdf_path: Path):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto(f"file://{html_path.absolute()}")
        await page.pdf(path=pdf_path, format="A4", print_background=True)
        await browser.close()
    return pdf_path

# ====================== DEMO MODE - REALISTIC COMPROMISED SCAN ======================
def get_demo_scan_data():
    """Returns realistic compromised hosts for demo purposes"""
    return [
        {
            "ip": "192.168.10.45",
            "hostname": "fileserver-old",
            "ports": [
                {"port": "3389", "service": "RDP", "version": "Microsoft Terminal Services"},
                {"port": "445", "service": "SMB", "version": "Microsoft Windows SMB"},
                {"port": "23", "service": "Telnet", "version": ""},
            ]
        },
        {
            "ip": "10.0.0.22",
            "hostname": "webserver-vuln",
            "ports": [
                {"port": "21", "service": "FTP", "version": "vsftpd 2.3.4"},
                {"port": "5900", "service": "VNC", "version": "RealVNC 4.0"},
                {"port": "1433", "service": "MSSQL", "version": "Microsoft SQL Server 2014"},
            ]
        },
        {
            "ip": "172.16.5.10",
            "hostname": "ssh-server",
            "ports": [
                {"port": "22", "service": "SSH", "version": "OpenSSH 7.2"},
                {"port": "3306", "service": "MySQL", "version": "MySQL 5.7"},
            ]
        },
        {
            "ip": "192.168.1.100",
            "hostname": "backup-server",
            "ports": [
                {"port": "3389", "service": "RDP", "version": ""},
                {"port": "445", "service": "SMB", "version": ""},
            ]
        }
    ]


# ====================== RUN THE SCRIPT ======================
if __name__ == "__main__":
    typer.run(analyze)
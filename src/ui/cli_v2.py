from datetime import datetime
import sqlite3
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

from core.threat_analyzer import ThreatAnalyzer 

console = Console()

def cli():

    """
    Main interface code


    Note: This version is a refactor of the cli.py file (made by myself) using ChatGPT
          Made to support the use of the Rich library, the older version of the code is mostly for reference
          and documenting the learning process. 
    """
    print_welcome_art()
    while True:
        try:
            console.rule("[bold cyan]WELCOME TO THREAT ANALYZER[/bold cyan]")
            console.print("[bold yellow]SELECT OPTION:[/bold yellow]")
            console.print("[green]1[/green] - Run Test")
            console.print("[green]2[/green] - Access Records")
            console.print("[red]CTRL+C to quit[/red]")

            user_input = Prompt.ask("> ", choices=["1", "2"], default="1")

            if user_input == "1":
                console.print("[bold cyan]Provide URL to application[/bold cyan]")
                target_url = Prompt.ask("> ")

                scanner = ThreatAnalyzer(target_url)
                vulnerabilities = scanner.scan()

                # Print summary in a panel
                summary = Panel.fit(
                    f"[bold green]Scan Complete![/bold green]\n"
                    f"[cyan]Total URLs scanned:[/cyan] {len(scanner.visited_urls)}\n"
                    f"[red]Vulnerabilities found:[/red] {len(vulnerabilities)}",
                    title="Scan Summary",
                    border_style="green"
                )
                console.print(summary)

            elif user_input == "2":
                access_records()

        except KeyboardInterrupt:
            console.print("\n[red]Quitting...[/red]")
            raise SystemExit()


def access_records():
    console.rule("[bold cyan]SCAN REPORTS[/bold cyan]")
    console.print("[green]1[/green] - Last Scan")
    console.print("[green]2[/green] - Find a Report")
    console.print("[green]3[/green] - Clean Data")
    choice = Prompt.ask("> ", choices=["1", "2", "3"])

    try:
        if choice == "1":
            with sqlite3.connect("vulns.db") as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, url, timestamp
                    FROM reports
                    ORDER BY timestamp DESC
                    LIMIT 1;
                """)
                last_report = cursor.fetchone()

                if last_report:
                    report_id, url, timestamp = last_report
                    cursor.execute("""
                        SELECT v.id, v.type, v.description
                        FROM vulns v
                        JOIN reports r ON r.id = v.report_id
                        WHERE r.id = ?;
                    """, (report_id,))
                    vulns = cursor.fetchall()
                    display_report(report_id, url, timestamp, vulns)
                else:
                    console.print("[yellow]No reports found.[/yellow]")

        elif choice == "2":
            console.print("[cyan]Search for a specific report (ID, URL, or Timestamp)[/cyan]")
            query = classify_input(Prompt.ask("> "))

            while query is None:
                console.print("[red]Invalid input.[/red] Try again.")
                query = classify_input(Prompt.ask("> "))

            with sqlite3.connect("vulns.db") as conn:
                cursor = conn.cursor()
                value, kind = query
                sql = f"SELECT id, url, timestamp FROM reports WHERE {kind} = ?;"
                cursor.execute(sql, (value,))
                report = cursor.fetchone()

                if not report:
                    console.print("[yellow]Couldn't find a report with this info...[/yellow]")
                else:
                    report_id, url, timestamp = report
                    cursor.execute("""
                        SELECT v.id, v.type, v.description
                        FROM vulns v
                        JOIN reports r ON r.id = v.report_id
                        WHERE r.id = ?;
                    """, (report_id,))
                    vulns = cursor.fetchall()
                    display_report(report_id, url, timestamp, vulns)

        elif choice == "3":
            if Confirm.ask("[red]Are you sure you want to erase all records in the database?[/red]"):
                with sqlite3.connect("vulns.db") as conn:
                    cursor = conn.cursor()
                    cursor.executescript("DELETE FROM reports; DELETE FROM vulns;")
                console.print("[green]Database reset![/green]")
            else:
                console.print("[yellow]Cancelled reset.[/yellow]")

    except Exception as e:
        console.print("[red]Error connecting to database![/red]")
        console.print_exception()
        raise SystemExit()


def display_report(report_id, url, timestamp, vulns):
    console.rule(f"[bold green]Report #{report_id}[/bold green]")
    console.print(f"[cyan]URL:[/cyan] {url}")
    console.print(f"[cyan]Timestamp:[/cyan] {timestamp}")

    if not vulns:
        console.print("[green]No vulnerabilities found in this report![/green]")
        return

    table = Table(title="Vulnerabilities", box=box.MINIMAL_DOUBLE_HEAD, header_style="bold magenta")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Type", style="red")
    table.add_column("Description", style="white")

    for v_id, v_type, v_desc in vulns:
        table.add_row(str(v_id), v_type, v_desc)

    console.print(table)


def classify_input(user_input: str):
    user_input = user_input.strip()

    if user_input.isdigit():
        return (user_input, "id")

    try:
        parsed = urlparse(user_input)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return (user_input, "url")
    except:
        pass

    date_formats = [
        "%Y-%m-%d", "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y", "%m/%d/%Y",
        "%d-%m-%Y", "%Y/%m/%d"
    ]
    for fmt in date_formats:
        try:
            datetime.strptime(user_input, fmt)
            return (user_input, "timestamp")
        except ValueError:
            continue

    return None

def print_welcome_art():
    ascii_art = r""" ______   __  __     ______     ______     ______     ______      ______     __   __     ______     __         __  __     ______     ______     ______    
/\__  _\ /\ \_\ \   /\  == \   /\  ___\   /\  __ \   /\__  _\    /\  __ \   /\ "-.\ \   /\  __ \   /\ \       /\ \_\ \   /\___  \   /\  ___\   /\  == \   
\/_/\ \/ \ \  __ \  \ \  __<   \ \  __\   \ \  __ \  \/_/\ \/    \ \  __ \  \ \ \-.  \  \ \  __ \  \ \ \____  \ \____ \  \/_/  /__  \ \  __\   \ \  __<   
   \ \_\  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\    \ \_\     \ \_\ \_\  \ \_\\"\_\  \ \_\ \_\  \ \_____\  \/\_____\   /\_____\  \ \_____\  \ \_\ \_\ 
    \/_/   \/_/\/_/   \/_/ /_/   \/_____/   \/_/\/_/     \/_/      \/_/\/_/   \/_/ \/_/   \/_/\/_/   \/_____/   \/_____/   \/_____/   \/_____/   \/_/ /_/ 
                                                                                                                                                          """
    console.print(f"[bold red]{ascii_art}[/bold red]")


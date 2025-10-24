from datetime import datetime
import sqlite3
from urllib.parse import urlparse


from core.threat_analyzer import ThreatAnalyzer 

def cli():
    """Main interface code"""
    while True:
        try:
            
            print("=== WELCOME TO THREAT ANALYZER ===")
            print()
            print("SELECT OPTION:")
            print("1 - RUN TEST")
            print("2 - ACCESS RECORDS")

            user_input = input("> ")
            print()

            # Checking if input is valid!
            while user_input not in ["1", "2"]:
                print("PLEASE PROVIDE VALID OPTION")

                user_input = input("> ")
                print() 
            


            if user_input == "1":
                print("PROVIDE URL TO APPLICATION")
                target_url = input("> ")

                scanner = ThreatAnalyzer(target_url)
                vulnerabilities = scanner.scan()

                # Print summary
                print(f"\nScan Complete!")
                print(f"Total URLs scanned: {len(scanner.visited_urls)}")
                print(f"Vulnerabilities found: {len(vulnerabilities)}")

            elif user_input == "2":
                try: 
                    print("==== SCAN REPORTS =====")
                    print("SELECT OPTION:")
                    print("1 - LAST SCAN")
                    print("2 - FIND A REPORT")
                    print("3 - CLEAN DATA")

                    user_input = input("> ")
                    print()

                    # Checking if input is valid!
                    while user_input not in ["1", "2", "3"]:
                        print("PLEASE PROVIDE VALID OPTION")
                        user_input = input("> ")
                        print()
                        
                    if user_input == "1":                      
                        with sqlite3.connect("vulns.db") as conn:
                            cursor = conn.cursor()

                            # Step 1: Get latest report
                            cursor.execute("""
                                SELECT id, url, timestamp
                                FROM reports
                                ORDER BY timestamp DESC
                                LIMIT 1;
                            """)
                            last_report = cursor.fetchone()

                            if last_report:
                                report_id, url, timestamp = last_report

                                # Step 2: Get all vulns for that report
                                cursor.execute("""
                                    SELECT v.id, v.type, v.description
                                    FROM vulns v
                                    JOIN reports r ON r.id = v.report_id
                                    WHERE r.id = ?;
                                """, (report_id,))
                                vulns = cursor.fetchall()

                                
                                result = {
                                    "report": {
                                        "id": report_id,
                                        "url": url,
                                        "timestamp": timestamp,
                                        "vulns": [{"id": v[0], "type": v[1], "description": v[2]} for v in vulns]
                                    }
                                }
                

                                print(result)
                    
                    # Searching for a specific report
                    if user_input == "2":
                        print("SEARCH FOR A SPECIFIC REPORT")
                        print("TYPE AN ID, URL OR TIMESTAMP... ")
                        query = classify_input(input("> "))

                        while query is None:
                            print("SEARCH FOR A SPECIFIC REPORT")
                            print("TYPE AN ID, URL OR TIMESTAMP... ")
                            print("EXAMPLES")
                            print("ID -> 1, 2, 3...")
                            print("URL -> https://juice-shop.herokuapp.com/")
                            print("TIMESTAMP -> 09/18/2025")


                            query = classify_input(input("> "))

                        with sqlite3.connect("vulns.db") as conn:
                            cursor = conn.cursor()

                            # Get the report based in the query
                            value, kind = query
                            if kind == "id":
                                cursor.execute("""
                                    SELECT id, url, timestamp
                                    FROM reports
                                    WHERE id = ?;
                                """, (value))
                            elif kind == "url":
                                cursor.execute("""
                                    SELECT id, url, timestamp
                                    FROM reports
                                    WHERE url = ?;
                                """, (value))
                            elif kind == "date_and_time":
                                cursor.execute("""
                                    SELECT id, url, timestamp
                                    FROM reports
                                    WHERE timestamp = ?;
                                """, (value))

                            report = cursor.fetchone()
                            if report is None: 
                                print("COUDN'T FIND A REPORT WITH THIS INFO...")
                                print("RETURNING TO HOMEPAGE...")
                                print()
                            else:
                                report_id, url, timestamp = report

                                # Step 2: Get all vulns for that report
                                cursor.execute("""
                                    SELECT v.id, v.type, v.description
                                    FROM vulns v
                                    JOIN reports r ON r.id = v.report_id
                                    WHERE r.id = ?;
                                """, (report_id,))
                                vulns = cursor.fetchall()

                                
                                result = {
                                    "report": {
                                        "id": report_id,
                                        "url": url,
                                        "timestamp": timestamp,
                                        "vulns": [{"id": v[0], "type": v[1], "description": v[2]} for v in vulns]
                                    }
                                }
                        print(result)


                    if user_input == "3":
                        user_input = ""
                        while user_input.lower() not in ["y", "n"]: 
                            print("ARE YOU SURE YOU WANT TO ERASE ALL IMPORTS IN THE DATABASE?")
                            user_input = input("y or n? > ").lower()
                            
                        if user_input == "n":
                            print("GOING BACK TO MENU...\n")
                            continue
                        elif user_input == "y":
                            print("RESETTING DATABASE...\n")
                            with sqlite3.connect("vulns.db") as conn:
                                cursor = conn.cursor()
                                cursor.executescript("""
                                    DELETE FROM reports;
                                    DELETE FROM vulns;
                                """)
                            print("DATABASE RESET!\n...")
                            continue
                                
                except Exception as e:
                    print("Error trying to connect to database!")
                    print(e)
                    print("Exiting...")
                    raise SystemExit()
                        
        except KeyboardInterrupt:
            print()
            print("Quitting...")
            raise SystemExit()
                        
def classify_input(user_input: str):
    user_input = user_input.strip()

    # Check if it's an ID (digits only)
    if user_input.isdigit():
        return (user_input, "id")

    # Check if it's a URL
    try:
        parsed = urlparse(user_input)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return (user_input, "url")
    except:
        pass

    # Check if it's a date and time
    date_formats = [
        "%Y-%m-%d",          # 2025-09-18
        "%Y-%m-%d %H:%M:%S", # 2025-09-18 14:30:00
        "%d/%m/%Y",          # 18/09/2025
        "%m/%d/%Y",          # 09/18/2025
        "%d-%m-%Y",          # 18-09-2025
        "%Y/%m/%d",          # 2025/09/18
    ]
    for fmt in date_formats:
        try:
            datetime.strptime(user_input, fmt)
            return (user_input, "date_and_time")
        except ValueError:
            continue

    # If none matched
    return None
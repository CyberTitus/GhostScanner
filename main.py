import requests, sys
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn, SpinnerColumn
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.layout import Layout
from rich.box import ROUNDED, HEAVY, DOUBLE
from rich import box
from pages import pages
import time
import random
import argparse
import threading
import queue
from queue import Empty  # Import Empty exception class
import json
import os
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Initialize Rich console
console = Console()

# User Agent list for stealth operations
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
]

def get_random_user_agent():
    """Return a random user agent for stealth operations."""
    return random.choice(user_agents)

def parse_arguments():
    """Parse command line arguments for operation parameters."""
    parser = argparse.ArgumentParser(description="GHOST SCANNER :: ADMIN PANEL INFILTRATOR v1.0")
    parser.add_argument("target", nargs="?", help="Target domain to scan")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for scanning (default: 5)")
    parser.add_argument("-o", "--output", help="Save results to specified file (JSON format by default)")
    parser.add_argument("-p", "--proxy", help="Use proxy for requests (format: http://proxy:port)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-m", "--mode", choices=["stealth", "aggressive", "deep", "passive", "evasion"], 
                      default="stealth", help="Operational mode (default: stealth)")
    parser.add_argument("--format", choices=["json", "txt"], default="json", 
                        help="Output format for saved results (default: json)")
    
    if len(sys.argv) == 1:
        return parser.parse_args(["-h"])
    
    return parser.parse_args()

# Clear terminal and display hacker banner
console.clear()

# Hacker-style ASCII banner
hacker_banner = """ [bold green]
        ░█▀▀░█░█░█▀█░█▀▀░▀█▀░█▀▀░█▀▀░█▀█░█▀█░█▀█░█▀▀░█▀▄
        ░█░█░█▀█░█░█░▀▀█░░█░░▀▀█░█░░░█▀█░█░█░█░█░█▀▀░█▀▄
        ░▀▀▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀                                                 
            [bold red][ [bold green]GHOST SCANNER v1.0[/] [bold red]]
[/]"""

console.print(hacker_banner)

# Glitch effect for subtitle
def glitch_text(text):
    # Return plain text without any random characters
    return text

subtitle = Text(glitch_text("Target: Admin Panels | Mode: Deep Recon"), style="green")
console.print(Panel(subtitle, border_style="green", box=box.HEAVY))

# Matrix-like divider
console.print("[dark_green]" + "".join(random.choice("01") for _ in range(80)) + "[/]")

# Print info with hacker style
console.print("[dim]Operator:[/] [bold green]@cybertituss[/]")
console.print("[bold red]⚠️ [blink]WARNING:[/] [red]For penetration testing purposes only. Use at your own risk.[/]")
console.print(f"[dim]Execute with [bold green]-h[/] or [bold green]--help[/] for operation parameters[/]")

# Matrix-like divider
console.print("[dark_green]" + "".join(random.choice("01") for _ in range(80)) + "[/]")
console.print()

# Display how to use information with hacker terminology
def show_usage_guide():
    usage_guide = Table(show_header=False, box=None)
    usage_guide.add_column(style="bold green", justify="left")
    usage_guide.add_column(style="white")
    
    usage_guide.add_row("Basic Execution:", "python main.py <target_domain>")
    usage_guide.add_row("Multi-threaded:", "python main.py <target_domain> --threads 10")
    usage_guide.add_row("Save Results:", "python main.py <target_domain> --output results.json")
    usage_guide.add_row("Use Proxy:", "python main.py <target_domain> --proxy http://127.0.0.1:8080")
    usage_guide.add_row("Change Mode:", "python main.py <target_domain> --mode aggressive")
    usage_guide.add_row("All Options:", "python main.py <target_domain> --threads 10 --output results.json --mode deep")
    usage_guide.add_row("Intel:", "python main.py -h")
    
    usage_text = """
This infiltration tool identifies vulnerable admin panels and control interfaces.
It probes the target system with over 400 known access paths.

[bold green]Operation Protocol:[/]
- Executes reconnaissance on target domain using selected mode
- Uses multi-threaded scanning for optimized performance
- Randomizes user agents to avoid detection
- Identifies exposed access points (status code 200)
- Provides complete intelligence report with exportable data

[bold green]Operation Modes:[/]
- [green]STEALTH[/]: Default balanced mode
- [yellow]AGGRESSIVE[/]: Fast scanning with more threads and shorter timeouts
- [blue]DEEP SCAN[/]: Additional paths and longer timeouts
- [cyan]PASSIVE[/]: Header-only requests for minimal footprint
- [magenta]EVASION[/]: Advanced WAF bypass techniques
    
[bold green]Intelligence Legend:[/]
- [green]Green responses (200)[/] indicate potential entry points
- [yellow]Yellow responses (301, 302)[/] indicate redirects/honeypots
- [red]Red responses (403, 404)[/] indicate secured/nonexistent endpoints
    
[bold red]OpSec Warning:[/] A 200 status doesn't guarantee admin access;
further exploitation may be required to confirm vulnerability.
"""
    
    how_to_panel = Panel(
        Text.assemble(usage_guide, Text(usage_text)),
        title="[bold green]📟 OPERATION MANUAL",
        border_style="green",
        box=box.HEAVY_EDGE,
        padding=(1, 2)
    )
    console.print(how_to_panel)
    console.print()

# Parse arguments
args = parse_arguments()

# Apply mode-specific settings
mode_display_name = "STEALTH RECON"
mode_thread_modifier = 1
mode_timeout_modifier = 1
mode_additional_paths = []

# Import additional paths for deep scan if needed
deep_scan_paths = []

if args.mode == "aggressive":
    mode_display_name = "AGGRESSIVE RECON"
    mode_thread_modifier = 3  # Triple the threads
    mode_timeout_modifier = 0.5  # Half the timeout
    
elif args.mode == "deep":
    mode_display_name = "DEEP SCAN"
    mode_thread_modifier = 1.5  # 50% more threads
    mode_timeout_modifier = 1.2  # 20% longer timeout
    
    # Load additional paths for deep scan
    deep_scan_paths = [
        "administrator.bak", "admin.bak", "login.old", "admin.old", "backup/", 
        "dev/", "development/", "staging/", "test/", "demo/", "beta/",
        "_admin", ".admin", "backend/", "manage/", "management/", "adm1n/", 
        "4dm1n/", "a-dmin/", "portal.php", "portal/", "dashboard/", "account/",
        "acc/", "secure/", "security/", "master/", "adm/", "moderator/", 
        "mod/", "cp/", "control/", "console/", "webadmin/", "author/", 
        "authors/", "root/", "sys/", "system/", "sys-admin/", "sysadmin/",
        "manager/", "admin1/", "admin2/", "wp-login/", "login.jsp", "login.asp",
        "panel.jsp", "panel.asp", "panel.aspx", "admin.jsp", "admin.asp", "admin.aspx"
    ]
    
elif args.mode == "passive":
    mode_display_name = "PASSIVE INTEL"
    mode_thread_modifier = 2  # Double the threads (since we're only getting headers)
    mode_timeout_modifier = 0.7  # 30% faster timeout
    
elif args.mode == "evasion":
    mode_display_name = "EVASION TACTICS"
    mode_thread_modifier = 0.7  # 30% fewer threads to stay under the radar
    mode_timeout_modifier = 1.5  # 50% longer timeout to appear more like regular traffic

# Apply the modifiers to the actual values
adjusted_threads = max(1, int(args.threads * mode_thread_modifier))
adjusted_timeout = args.timeout * mode_timeout_modifier

# Combine standard paths with any additional mode-specific paths
scan_paths = pages.copy()
if deep_scan_paths:
    scan_paths.extend(deep_scan_paths)

# Show usage guide for help flag
# No need for explicit help check since argparse handles it automatically

# Get target
if not args.target:
    show_usage_guide()
    usage_panel = Panel(
        f"[green]python [green]{sys.argv[0]} [red]<target>[/]",
        title="[bold red]MISSION ABORTED: No Target Specified",
        border_style="red",
        box=box.HEAVY_EDGE
    )
    console.print(usage_panel)
    sys.exit(1)

target = args.target

# Normalize target URL
if target[0:8] != "https://" and target[0:7] != "http://":
    target = "https://" + target
if target[-1] != "/":
    target = target + "/"

# Display scan info with hacker style
scan_info = Table.grid(padding=1)
scan_info.add_column(style="green", justify="right")
scan_info.add_column(style="bold green")

scan_info.add_row("TARGET:", target)
scan_info.add_row("PAYLOADS:", str(len(scan_paths)))
scan_info.add_row("THREADS:", str(adjusted_threads))
scan_info.add_row("TIMESTAMP:", time.strftime("%H:%M:%S", time.localtime()))
scan_info.add_row("MODE:", mode_display_name)

if args.proxy:
    scan_info.add_row("PROXY:", args.proxy)
if args.no_verify:
    scan_info.add_row("TLS VERIFY:", "DISABLED")
if args.output:
    scan_info.add_row("EXFIL FILE:", args.output)

console.print(Panel(scan_info, title="[bold green]:: MISSION PARAMETERS ::", border_style="green", box=box.HEAVY_EDGE))
console.print()

# Initialize results storage
found_pages = []
all_results = []
result_queue = queue.Queue()
error_count = 0
lock = threading.Lock()

def scan_url(page, progress, scan_task):
    """Thread worker function to scan a single URL."""
    global error_count
    
    current_url = target + page
    
    # Set up request parameters
    request_kwargs = {
        'timeout': adjusted_timeout,
        'verify': not args.no_verify,
        'headers': {'User-Agent': get_random_user_agent()}
    }
    
    # Add evasion mode headers if selected
    if args.mode == "evasion":
        # Add realistic headers to appear as legitimate browser
        request_kwargs['headers'].update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Referer': f'https://www.google.com/search?q={target.split("//")[1].split("/")[0].replace(".", "+")}'
        })
    
    if args.proxy:
        request_kwargs['proxies'] = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    try:
        # For passive mode, only get headers
        if args.mode == "passive":
            response = requests.head(current_url, **request_kwargs)
            
            # If we get a non-404 response, do a followup GET for content length
            content_length = 0
            if response.status_code != 404:
                if 'Content-Length' in response.headers:
                    content_length = int(response.headers['Content-Length'])
                else:
                    # Quick GET to get content length, with short timeout
                    try:
                        head_kwargs = request_kwargs.copy()
                        head_kwargs['timeout'] = min(1.0, adjusted_timeout)
                        r = requests.get(current_url, **head_kwargs)
                        content_length = len(r.content)
                    except:
                        content_length = 0
        else:
            response = requests.get(current_url, **request_kwargs)
            content_length = len(response.content)
            
        status_code = response.status_code
        
        # Add delay between requests for evasion mode
        if args.mode == "evasion":
            time.sleep(random.uniform(0.5, 2.0))
        
        # Store result
        result = {
            "url": current_url,
            "page": page,
            "status_code": status_code,
            "content_length": content_length,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mode": args.mode
        }
        
        # Add to result queue for thread-safe processing
        result_queue.put(result)
        
        # Handle found pages (status 200)
        if status_code == 200:
            with lock:
                # Different message for passive mode
                if args.mode == "passive":
                    found_text = Text.assemble(
                        ("✅ ", "green"),
                        ("ENDPOINT DETECTED! ", "bold green"),
                        (f"{page}", "bold green"),
                        (" → ", "white"),
                        (f"{current_url}", "green underline"),
                        (f" [Status: {status_code}]", "green")
                    )
                else:
                    found_text = Text.assemble(
                        ("✅ ", "green"),
                        ("VULNERABILITY DETECTED! ", "bold green"),
                        (f"{page}", "bold green"),
                        (" → ", "white"),
                        (f"{current_url}", "green underline"),
                        (f" [Status: {status_code}]", "green")
                    )
                progress.console.print(found_text)
        
    except requests.exceptions.ConnectionError:
        with lock:
            error_count += 1
            if args.verbose:
                progress.console.print(f"[red]CONNECTION FAILURE for {page}[/]")
    except requests.exceptions.Timeout:
        with lock:
            error_count += 1
            if args.verbose:
                progress.console.print(f"[yellow]⚠️ Timeout encountered on endpoint [green]{page}[/]")
    except requests.exceptions.RequestException as e:
        with lock:
            error_count += 1
            if args.verbose:
                progress.console.print(f"[red]⚠️ Request error: {str(e)} - {page}[/]")
    except Exception as e:
        with lock:
            error_count += 1
            if args.verbose:
                progress.console.print(f"[red]❌ Exploit failed: {str(e)}[/]")
    
    # Update progress regardless of result
    with lock:
        progress.update(scan_task, advance=1)

# Create progress display with hacker theme
try:
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("[green]{task.completed}[/]/[bold green]{task.total}[/]"),
        TimeRemainingColumn(),
        expand=True,
        console=console
    ) as progress:
        scan_task = progress.add_task("[bold]INFILTRATING SERVER...", total=len(scan_paths))
        
        # Create thread-safe queue of URLs to scan
        url_queue = queue.Queue()
        for page in scan_paths:
            url_queue.put(page)
        
        # Define worker function for threads
        def worker(queue, progress, scan_task):
            global error_count  # Add global declaration
            while True:
                try:
                    page = queue.get(block=False)
                    try:
                        scan_url(page, progress, scan_task)
                    except Exception as e:
                        with lock:
                            error_count += 1
                            if args.verbose:
                                progress.console.print(f"[red]Error in worker thread: {str(e)}[/]")
                    finally:
                        queue.task_done()
                except Empty:
                    break
        
        # Create and start worker threads
        threads = []
        thread_count = min(adjusted_threads, len(scan_paths))
        for _ in range(thread_count):
            thread = threading.Thread(
                target=worker,
                args=(url_queue, progress, scan_task),
                daemon=True
            )
            thread.start()
            threads.append(thread)
        
        # Wait for all work to be processed
        try:
            # Set a timeout in case of stuck threads
            url_queue.join()
        except KeyboardInterrupt:
            console.print("[bold red]Operation aborted by user.[/]")
            sys.exit(1)
        
        # Wait for all threads to complete
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=1.0)  # Add timeout to prevent hanging
        
        # Process results from the queue
        while True:
            try:
                result = result_queue.get(block=False)
                all_results.append(result)
                if result["status_code"] == 200:
                    found_pages.append(result)
                result_queue.task_done()
            except Empty:
                break
except KeyboardInterrupt:
    console.print("\n[bold red]Operation aborted by user.[/]")
    sys.exit(1)

console.print()

# Matrix-like divider
console.print("[dark_green]" + "".join(random.choice("01") for _ in range(80)) + "[/]")

# Display results summary in a hacker style
console.print(Panel("[bold green]:: INTEL REPORT ::", style="green", box=HEAVY))

# Found pages section
if found_pages:
    found_table = Table(
        show_header=True,
        header_style="bold green",
        box=box.HEAVY_EDGE,
        border_style="green"
    )
    found_table.add_column("Endpoint", style="green")
    found_table.add_column("Access URL", style="green")
    found_table.add_column("Content Size", style="green")
    
    for result in found_pages:
        found_table.add_row(
            result["page"], 
            result["url"], 
            f"{result['content_length']} bytes"
        )
    
    console.print(Panel(
        found_table,
        title=f"[bold green]✅ {len(found_pages)} VULNERABLE ENDPOINTS DETECTED",
        border_style="green",
        box=box.HEAVY_EDGE
    ))
else:
    console.print(Panel(
        "[yellow]No accessible entry points discovered with status 200.",
        title="[bold yellow]⚠️ TARGET SECURED",
        border_style="yellow",
        box=box.HEAVY_EDGE
    ))

# Status code distribution in a hacker-styled table
status_counts = {}
for result in all_results:
    status = result["status_code"]
    if status in status_counts:
        status_counts[status] += 1
    else:
        status_counts[status] = 1

status_table = Table(show_header=True, box=box.HEAVY_EDGE, border_style="green")
status_table.add_column("Response", style="bold")
status_table.add_column("Count", style="green")
status_table.add_column("Analysis", style="italic")

status_meanings = {
    200: "SUCCESS - Entry point identified",
    301: "REDIRECT - Permanent honeypot",
    302: "REDIRECT - Temporary diversion",
    307: "REDIRECT - Temporary redirection",
    400: "ERROR - Malformed request",
    401: "LOCKED - Authentication required",
    403: "FORBIDDEN - Access denied by firewall",
    404: "NOT FOUND - Endpoint doesn't exist",
    500: "SERVER ERROR - Potential vulnerability",
}

for status, count in sorted(status_counts.items()):
    status_color = "green" if status == 200 else "yellow" if status < 400 else "red"
    meaning = status_meanings.get(status, "")
    status_table.add_row(f"[{status_color}]{status}[/]", str(count), meaning)

console.print(Panel(
    status_table,
    title="[bold green]SERVER RESPONSE ANALYSIS",
    border_style="green",
    box=box.HEAVY_EDGE
))

# Operations summary table
ops_summary = Table(show_header=False, box=box.HEAVY_EDGE, border_style="cyan")
ops_summary.add_column(style="cyan", justify="right")
ops_summary.add_column(style="bold green")

ops_summary.add_row("Total Endpoints Probed:", str(len(all_results)))
ops_summary.add_row("Access Points Found:", str(len(found_pages)))
ops_summary.add_row("Error Encounters:", str(error_count))
ops_summary.add_row("Operation Mode:", mode_display_name)

# Calculate success rate safely, avoiding division by zero
if len(scan_paths) > 0:
    success_rate = (len(all_results) - error_count) / len(scan_paths) * 100
    success_rate_str = f"{success_rate:.2f}%"
else:
    success_rate_str = "N/A"
ops_summary.add_row("Success Rate:", success_rate_str)

ops_summary.add_row("Threads Deployed:", str(adjusted_threads))
ops_summary.add_row("Timeout Setting:", f"{adjusted_timeout:.1f}s")

console.print(Panel(
    ops_summary,
    title="[bold cyan]OPERATION SUMMARY",
    border_style="cyan",
    box=box.HEAVY_EDGE
))

# Save results to file if specified
if args.output:
    try:
        output_file = args.output
        
        # For txt format, ensure the extension is correct
        if args.format == "txt" and not output_file.lower().endswith(".txt"):
            output_file = f"{output_file.rsplit('.', 1)[0] if '.' in output_file else output_file}.txt"
        # For json format, ensure the extension is correct
        elif args.format == "json" and not output_file.lower().endswith(".json"):
            output_file = f"{output_file.rsplit('.', 1)[0] if '.' in output_file else output_file}.json"
        
        if args.format == "json":
            # Prepare export data
            export_data = {
                "target": target,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "total_endpoints": len(scan_paths),
                "scanned_endpoints": len(all_results),
                "operation_mode": args.mode,
                "mode_display": mode_display_name,
                "threads": adjusted_threads,
                "timeout": adjusted_timeout,
                "found_pages": [
                    {
                        "page": result["page"],
                        "url": result["url"],
                        "status_code": result["status_code"],
                        "content_length": result["content_length"],
                        "timestamp": result["timestamp"]
                    } for result in found_pages
                ],
                "status_distribution": {str(status): count for status, count in status_counts.items()},
                "error_count": error_count
            }
            
            # Save to JSON file
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=4)
        
        else:  # text format
            with open(output_file, 'w') as f:
                # Write header
                f.write("=======================================================\n")
                f.write("           GHOST SCANNER :: INTEL REPORT              \n")
                f.write("=======================================================\n\n")
                
                # Mission parameters
                f.write("MISSION PARAMETERS:\n")
                f.write("------------------\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
                f.write(f"Operation Mode: {mode_display_name}\n")
                f.write(f"Total Endpoints: {len(scan_paths)}\n")
                f.write(f"Threads: {adjusted_threads}\n")
                f.write(f"Timeout: {adjusted_timeout:.1f}s\n")
                if args.proxy:
                    f.write(f"Proxy: {args.proxy}\n")
                f.write(f"SSL Verification: {'Disabled' if args.no_verify else 'Enabled'}\n\n")
                
                # Found pages
                f.write("VULNERABLE ENDPOINTS DETECTED:\n")
                f.write("-----------------------------\n")
                if found_pages:
                    for i, result in enumerate(found_pages, 1):
                        f.write(f"{i}. Endpoint: {result['page']}\n")
                        f.write(f"   URL: {result['url']}\n")
                        f.write(f"   Status: {result['status_code']}\n")
                        f.write(f"   Content Size: {result['content_length']} bytes\n")
                        f.write(f"   Timestamp: {result['timestamp']}\n")
                        f.write("   ----------------------------------------------------\n")
                else:
                    f.write("No accessible entry points discovered with status 200.\n\n")
                
                # Status code distribution
                f.write("SERVER RESPONSE ANALYSIS:\n")
                f.write("-----------------------\n")
                for status, count in sorted(status_counts.items()):
                    meaning = status_meanings.get(status, "")
                    f.write(f"Status {status}: {count} occurrences - {meaning}\n")
                f.write("\n")
                
                # Operation summary
                f.write("OPERATION SUMMARY:\n")
                f.write("-----------------\n")
                f.write(f"Total Endpoints Probed: {len(all_results)}\n")
                f.write(f"Access Points Found: {len(found_pages)}\n")
                f.write(f"Error Encounters: {error_count}\n")
                f.write(f"Success Rate: {success_rate_str}\n\n")
                
                # Add tactical recommendations
                f.write("TACTICAL RECOMMENDATIONS:\n")
                f.write("------------------------\n")
                if len(found_pages) > 0:
                    f.write("- Secure all exposed admin interfaces immediately\n")
                    f.write("- Implement IP-based access restrictions\n")
                    f.write("- Add multi-factor authentication\n")
                    f.write("- Consider renaming default admin paths\n")
                    f.write("- Move admin interfaces to internal networks\n")
                else:
                    f.write("- Consider running a deeper scan\n")
                    f.write("- Test with different user-agents\n")
                    f.write("- Investigate any redirect endpoints\n")
                    f.write("- Check for custom admin paths\n")
                f.write("\n")
                
                f.write("=======================================================\n")
                f.write("CONFIDENTIAL: For authorized penetration testing only.\n")
                f.write("This report contains sensitive security information.\n")
                f.write("=======================================================\n")
        
        console.print(Panel(
            f"[green]Results successfully exported to: [bold]{output_file}[/] ({args.format.upper()} format)",
            title="[bold green]DATA EXFILTRATION COMPLETE",
            border_style="green",
            box=box.HEAVY_EDGE
        ))
    except Exception as e:
        console.print(Panel(
            f"[red]Failed to save results: {str(e)}",
            title="[bold red]EXFILTRATION FAILURE",
            border_style="red",
            box=box.HEAVY_EDGE
        ))

# Matrix-like divider
console.print("[dark_green]" + "".join(random.choice("01") for _ in range(80)) + "[/]")

# Completion message
finish_time = time.strftime("%H:%M:%S", time.localtime())
completion = Text.assemble(
    ("🔓 MISSION COMPLETED at ", "green"),
    (finish_time, "bold green"),
    (" | Exfiltrating data...", "green blink")
)
console.print(Panel(completion, box=box.HEAVY_EDGE, border_style="green"))

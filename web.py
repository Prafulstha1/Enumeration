import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import dns.resolver 
import requests 
import socket
from bs4 import BeautifulSoup 
import whois
import csv
import json
from datetime import datetime
from tkinter import messagebox
import sqlite3
from tkinter import ttk


def check_xss(url):
        payload = '<script>alert("XSS vulnerability")</script>'
        response = requests.get(url + payload)
        if payload in response.text:
            messagebox.showwarning("XSS Vulnerability Found", f"XSS vulnerability found in: {url}")

def check_sql_injection(url):
        payload = "1' OR '1'='1"
        response = requests.get(url + "?id=" + payload)
        if "error" in response.text:
            messagebox.showwarning("SQL Injection Vulnerability Found", f"SQL injection vulnerability found in: {url}")

def scan_url(entry):
        target_url = entry.get()
        if not target_url:
            messagebox.showwarning("Error", "Please enter a valid URL.")
            return

        try:
            check_xss(target_url)
            check_sql_injection(target_url)
            messagebox.showinfo("Scan Complete", "Scan complete.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error occurred while scanning URL:\n{str(e)}")

def url_vulnerability_scanner():
    root = tk.Tk()
    root.title("SQL and XSS Vulnerability Scanner")

    label = tk.Label(root, text="Enter the target URL:")
    label.pack(pady=10)

    entry = tk.Entry(root, width=50)
    entry.pack(pady=5)

    scan_button = tk.Button(root, text="Scan", command=lambda: scan_url(entry))
    scan_button.pack(pady=10)

    root.mainloop()


def execute_second_code():

    def enumerate_dns_records():
        domain = dns_domain_entry.get()
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        result_text.delete(1.0, tk.END)

        for record_type in record_types:
            try:
                answers = dns.resolver.query(domain, record_type)
                result_text.insert(tk.END, f"DNS {record_type} records for {domain}:\n")
                for answer in answers:
                    result_text.insert(tk.END, f"{answer.to_text()}\n")
                result_text.insert(tk.END, "-----------------------------------\n")
            except dns.resolver.NoAnswer:
                result_text.insert(tk.END, f"No {record_type} record found for {domain}\n")
                result_text.insert(tk.END, "-----------------------------------\n")
            except dns.resolver.NXDOMAIN:
                result_text.insert(tk.END, f"Domain '{domain}' does not exist\n")
                break
            except dns.exception.Timeout:
                result_text.insert(tk.END, "DNS resolution timeout occurred\n")
                break

    def analyze_http_response():
        url = http_url_entry.get()
        result_text.delete(1.0, tk.END)

        try:
            response = requests.get(url)
            
            result_text.insert(tk.END, f"URL: {response.url}\n")
            result_text.insert(tk.END, f"Status Code: {response.status_code}\n")
            result_text.insert(tk.END, "Headers:\n")
            for header, value in response.headers.items():
                result_text.insert(tk.END, f"{header}: {value}\n")
            result_text.insert(tk.END, "Response Body:\n")
            result_text.insert(tk.END, response.text)

        except requests.exceptions.RequestException as e:
            result_text.insert(tk.END, "HTTP response analysis failed: " + str(e))

    def scan_ports():
        hostname = port_hostname_entry.get()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Scanning ports for {hostname}...\n\n")

        try:
            target_ip = socket.gethostbyname(hostname)
            common_ports = [21, 22, 80, 443, 3389]

            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Timeout for connection
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    result_text.insert(tk.END, f"Port {port} ({service}) is open\n")
                sock.close()

        except socket.gaierror:
            result_text.insert(tk.END, "Invalid hostname or unable to resolve IP address")

    def find_subdomains():
        domain = subdomain_domain_entry.get()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Finding subdomains for {domain}...\n\n")

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url)
        data = response.json()

        subdomains = set()
        for item in data:
            name_value = item['name_value']
            subdomains.add(name_value)

        if len(subdomains) > 0:
            result_text.insert(tk.END, f"Subdomains for {domain}:\n")
            for subdomain in subdomains:
                result_text.insert(tk.END, f"{subdomain}\n")
        else:
            result_text.insert(tk.END, "No subdomains found")

    def content_fingerprinting():
        url = content_url_entry.get()
        result_text.delete(1.0, tk.END)

        try:
            response = requests.get(url)
            html_content = response.text
            
            # Check for specific patterns or keywords in the HTML content
            if "WordPress" in html_content:
                result_text.insert(tk.END, "WordPress CMS detected.\n")
            if "Joomla" in html_content:
                result_text.insert(tk.END, "Joomla CMS detected.\n")
            if "Drupal" in html_content:
                result_text.insert(tk.END, "Drupal CMS detected.\n")
            if "Magento" in html_content:
                result_text.insert(tk.END, "Magento CMS detected.\n")
            if "Shopify" in html_content:
                result_text.insert(tk.END, "Shopify CMS detected.\n")
            if "React" in html_content:
                result_text.insert(tk.END, "React framework detected.\n")
            if "Vue" in html_content:
                result_text.insert(tk.END, "Vue.js framework detected.\n")
            if "AngularJS" in html_content:
                result_text.insert(tk.END, "AngularJS framework detected.\n")
            if "Laravel" in html_content:
                result_text.insert(tk.END, "Laravel framework detected.\n")
            if "Django" in html_content:
                result_text.insert(tk.END, "Django framework detected.\n")
            if "Ruby on Rails" in html_content:
                result_text.insert(tk.END, "Ruby on Rails framework detected.\n")
            if "ASP.NET" in html_content:
                result_text.insert(tk.END, "ASP.NET framework detected.\n")
            if "Express.js" in html_content:
                result_text.insert(tk.END, "Express.js framework detected.\n")
            if "Bootstrap" in html_content:
                result_text.insert(tk.END, "Bootstrap framework detected.\n")
            if "jQuery" in html_content:
                result_text.insert(tk.END, "jQuery library detected.\n")
            if "Angular" in html_content:
                result_text.insert(tk.END, "Angular framework detected.\n")
            if "Vue" in html_content:
                result_text.insert(tk.END, "Vue.js framework detected.\n")
            # Add more patterns or keywords as needed for additional technologies
            
        except requests.exceptions.RequestException as e:
            result_text.insert(tk.END, "Content fingerprinting failed: " + str(e))

    def scrape_website():
        url = scrape_url_entry.get()
        result_text.delete(1.0, tk.END)

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Example: Scraping the page title
            page_title = soup.title.string
            result_text.insert(tk.END, f"Page Title: {page_title}\n\n")
            
            # Example: Scraping all links on the page
            links = soup.find_all('a')
            result_text.insert(tk.END, "Links:\n")
            for link in links:
                link_url = link.get('href')
                link_text = link.string
                result_text.insert(tk.END, f"{link_text}: {link_url}\n")
                
            # Add more scraping logic as needed
            
        except requests.exceptions.RequestException as e:
            result_text.insert(tk.END, "Web scraping failed: " + str(e))

    def perform_whois_lookup():
        domain = whois_domain_entry.get()
        result_text.delete(1.0, tk.END)

        try:
            w = whois.whois(domain)
            result_text.insert(tk.END, f"Domain Name: {w.domain_name}\n")
            result_text.insert(tk.END, f"Registrar: {w.registrar}\n")
            result_text.insert(tk.END, f"Registration Date: {w.creation_date}\n")
            result_text.insert(tk.END, f"Expiration Date: {w.expiration_date}\n")
            result_text.insert(tk.END, f"Name Servers: {w.name_servers}\n")
            result_text.insert(tk.END, f"Registrant Name: {w.name}\n")
            result_text.insert(tk.END, f"Registrant Organization: {w.org}\n")
            result_text.insert(tk.END, f"Registrant Email: {w.email}\n")
            result_text.insert(tk.END, f"Registrant Phone: {w.phone}\n")
            result_text.insert(tk.END, f"Updated Date: {w.updated_date}\n")
            result_text.insert(tk.END, f"Whois Server: {w.whois_server}\n")
            result_text.insert(tk.END, f"Raw Whois Data:\n{w.text}")

        except Exception as e:
            result_text.insert(tk.END, "Whois lookup failed: " + str(e))

    def perform_nslookup():
        domain = nslookup_domain_entry.get()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Performing nslookup for {domain}...\n\n")

        try:
            answers = dns.resolver.resolve(domain, 'A')
            result_text.insert(tk.END, f"IP Addresses for {domain}:\n")
            for answer in answers:
                result_text.insert(tk.END, f"{answer}\n")
        except dns.resolver.NoAnswer:
            result_text.insert(tk.END, f"No A record found for {domain}\n")
        except dns.resolver.NXDOMAIN:
            result_text.insert(tk.END, f"Domain '{domain}' does not exist\n")
        except dns.exception.Timeout:
            result_text.insert(tk.END, "DNS resolution timeout occurred\n")

    def generate_report():
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"report_{timestamp}.txt"
        with open(report_filename, 'w') as file:
            file.write(result_text.get(1.0, tk.END))
        result_text.insert(tk.END, f"\nReport generated: {report_filename}\n")

    def export_csv():
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        csv_filename = f"results_{timestamp}.csv"
        with open(csv_filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Result"])
            writer.writerow([result_text.get(1.0, tk.END)])
        result_text.insert(tk.END, f"\nResults exported as CSV: {csv_filename}\n")

    def export_json():
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        json_filename = f"results_{timestamp}.json"
        data = {"result": result_text.get(1.0, tk.END)}
        with open(json_filename, 'w') as file:
            json.dump(data, file)
        result_text.insert(tk.END, f"\nResults exported as JSON: {json_filename}\n")

    def export_html():
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        html_filename = f"results_{timestamp}.html"
        with open(html_filename, 'w') as file:
            file.write(f"<pre>{result_text.get(1.0, tk.END)}</pre>")
        result_text.insert(tk.END, f"\nResults exported as HTML: {html_filename}\n")

    def exit_application():
        window.destroy()

    # Create the main window
    window = tk.Tk()
    window.title("Web Enumuration Tool")
    window.geometry("1000x1000")
    
    # Create DNS analysis section
    dns_frame = tk.LabelFrame(window, text="DNS Record Enumeration", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    dns_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    dns_domain_label = tk.Label(dns_frame, text="Enter the domain to enumerate DNS records:", font=("Helvetica", 12))
    dns_domain_label.pack()

    dns_domain_entry = tk.Entry(dns_frame, font=("Helvetica", 12))
    dns_domain_entry.pack(pady=5)

    dns_button = tk.Button(dns_frame, text="Enumerate DNS", command=enumerate_dns_records, font=("Helvetica", 12, "bold"))
    dns_button.pack(pady=5)

    # Create HTTP analysis section
    http_frame = tk.LabelFrame(window, text="HTTP Response Analysis", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    http_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

    http_url_label = tk.Label(http_frame, text="Enter the URL to analyze:", font=("Helvetica", 12))
    http_url_label.pack()

    http_url_entry = tk.Entry(http_frame, font=("Helvetica", 12))
    http_url_entry.pack(pady=5)

    http_button = tk.Button(http_frame, text="Analyze HTTP Response", command=analyze_http_response, font=("Helvetica", 12, "bold"))
    http_button.pack(pady=5)

    # Create port scanning section
    port_frame = tk.LabelFrame(window, text="Port Scanning", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    port_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

    port_hostname_label = tk.Label(port_frame, text="Enter the hostname to scan:", font=("Helvetica", 12))
    port_hostname_label.pack()

    port_hostname_entry = tk.Entry(port_frame, font=("Helvetica", 12))
    port_hostname_entry.pack(pady=5)

    port_button = tk.Button(port_frame, text="Scan Ports", command=scan_ports, font=("Helvetica", 12, "bold"))
    port_button.pack(pady=5)

    # Create subdomain finding section
    subdomain_frame = tk.LabelFrame(window, text="Subdomain Finder", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    subdomain_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

    subdomain_domain_label = tk.Label(subdomain_frame, text="Enter the domain to find subdomains:", font=("Helvetica", 12))
    subdomain_domain_label.pack()

    subdomain_domain_entry = tk.Entry(subdomain_frame, font=("Helvetica", 12))
    subdomain_domain_entry.pack(pady=5)

    subdomain_button = tk.Button(subdomain_frame, text="Find Subdomains", command=find_subdomains, font=("Helvetica", 12, "bold"))
    subdomain_button.pack(pady=5)

    # Create content fingerprinting section
    content_frame = tk.LabelFrame(window, text="Web Technology Detection", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    content_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

    content_url_label = tk.Label(content_frame, text="Enter the URL to analyze:", font=("Helvetica", 12))
    content_url_label.pack()

    content_url_entry = tk.Entry(content_frame, font=("Helvetica", 12))
    content_url_entry.pack(pady=5)

    content_button = tk.Button(content_frame, text="Analyze Content", command=content_fingerprinting, font=("Helvetica", 12, "bold"))
    content_button.pack(pady=5)

    # Create website scraping section
    scrape_frame = tk.LabelFrame(window, text="Website Scraping", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    scrape_frame.grid(row=2, column=1, padx=10, pady=10, sticky="nsew")

    scrape_url_label = tk.Label(scrape_frame, text="Enter the URL to scrape:", font=("Helvetica", 12))
    scrape_url_label.pack()

    scrape_url_entry = tk.Entry(scrape_frame, font=("Helvetica", 12))
    scrape_url_entry.pack(pady=5)

    scrape_button = tk.Button(scrape_frame, text="Scrape Website", command=scrape_website, font=("Helvetica", 12, "bold"))
    scrape_button.pack(pady=5)

    # Create WHOIS lookup section
    whois_frame = tk.LabelFrame(window, text="WHOIS Lookup", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    whois_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

    whois_domain_label = tk.Label(whois_frame, text="Enter the domain to perform WHOIS lookup:", font=("Helvetica", 12))
    whois_domain_label.pack()

    whois_domain_entry = tk.Entry(whois_frame, font=("Helvetica", 12))
    whois_domain_entry.pack(pady=5)

    whois_button = tk.Button(whois_frame, text="Perform Lookup", command=perform_whois_lookup, font=("Helvetica", 12, "bold"))
    whois_button.pack(pady=5)

    # Create nslookup section
    nslookup_frame = tk.LabelFrame(window, text="nslookup", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    nslookup_frame.grid(row=3, column=1, padx=10, pady=10, sticky="nsew")

    nslookup_domain_label = tk.Label(nslookup_frame, text="Enter the domain to perform nslookup:", font=("Helvetica", 12))
    nslookup_domain_label.pack()

    nslookup_domain_entry = tk.Entry(nslookup_frame, font=("Helvetica", 12))
    nslookup_domain_entry.pack(pady=5)

    nslookup_button = tk.Button(nslookup_frame, text="Perform nslookup", command=perform_nslookup, font=("Helvetica", 12, "bold"))
    nslookup_button.pack(pady=5)

    # Create the result text widget
    result_frame = tk.LabelFrame(window, text="Result", font=("Helvetica", 16, "bold"), padx=20, pady=10)
    result_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    result_text = ScrolledText(result_frame, height=15, font=("Courier", 12))
    result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    result_text.bind("<MouseWheel>", lambda event: result_text.yview_scroll(int(-1 * (event.delta / 120)), "units"))

    # Create the menu bar
    menu_bar = tk.Menu(window)
    window.config(menu=menu_bar)

    # Create the File menu
    file_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Generate Report", command=generate_report)
    file_menu.add_separator()
    file_menu.add_command(label="Export as CSV", command=export_csv)
    file_menu.add_command(label="Export as JSON", command=export_json)
    file_menu.add_command(label="Export as HTML", command=export_html)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=exit_application)

    
    # Create the URL Vulnerability Scanner menu
    scanner_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="SQL and XSS Vulnerability Scanner", menu=scanner_menu)
    scanner_menu.add_command(label="Scan URL", command=url_vulnerability_scanner)

    # Configure grid weights for responsive layout
    window.grid_columnconfigure(0, weight=1)
    window.grid_columnconfigure(1, weight=1)
    window.grid_rowconfigure(0, weight=1)
    window.grid_rowconfigure(1, weight=1)
    window.grid_rowconfigure(2, weight=1)
    window.grid_rowconfigure(3, weight=1)
    window.grid_rowconfigure(4, weight=1)

    window.mainloop()

# Function to create the database table
def create_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# Function to insert a new user into the database
def insert_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

# Function to check if the username and password match in the database
def login_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

# Function to handle the signup button click
def signup():
    username = signup_username.get()
    password = signup_password.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty.")
    else:
        try:
            insert_user(username, password)
            messagebox.showinfo("Success", "Account created successfully.")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists. Please choose a different one.")

# Function to handle the login button click
def login():
    username = login_username.get()
    password = login_password.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty.")
    else:
        user = login_user(username, password)
        if user:
            messagebox.showinfo("Success", "Login successful.")
            # Close the login window after successful login
            root.destroy()
            # Call the function to execute the second code here
            execute_second_code()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

# GUI setup of Authentication System
root = tk.Tk()
root.title("Authentication System")
# Set a fixed window size
window_width = 600
window_height = 550
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x_coordinate = (screen_width / 2) - (window_width / 2)
y_coordinate = (screen_height / 2) - (window_height / 2)
root.geometry(f"{window_width}x{window_height}+{int(x_coordinate)}+{int(y_coordinate)}")

# Set the theme to 'vista' for a modern look (you can experiment with other available themes as well)
style = ttk.Style()
style.theme_use('clam')

# Create the table for authentication (assuming you have a function named create_table)
create_table()

# Signup section
signup_frame = ttk.Frame(root, padding=20)
signup_frame.pack()

signup_label = ttk.Label(signup_frame, text="Signup", font=("Helvetica", 24, "bold"), foreground="black")
signup_label.pack(pady=10)

signup_username_label = ttk.Label(signup_frame, text="Username:", font=("Helvetica", 16, "bold"), foreground="black")
signup_username_label.pack()
signup_username = ttk.Entry(signup_frame, font=("Helvetica", 16))
signup_username.pack()

signup_password_label = ttk.Label(signup_frame, text="Password:", font=("Helvetica", 16, "bold"), foreground="black")
signup_password_label.pack()
signup_password = ttk.Entry(signup_frame, show="*", font=("Helvetica", 16))
signup_password.pack()

signup_button = ttk.Button(signup_frame, text="Signup", command=signup, style="Accent.TButton")
signup_button.pack(pady=10)

# Login section
login_frame = ttk.Frame(root, padding=20)
login_frame.pack()

login_label = ttk.Label(login_frame, text="Login", font=("Helvetica", 24, "bold"), foreground="black")
login_label.pack(pady=10)

login_username_label = ttk.Label(login_frame, text="Username:", font=("Helvetica", 16, "bold"), foreground="black")
login_username_label.pack()
login_username = ttk.Entry(login_frame, font=("Helvetica", 16))
login_username.pack()

login_password_label = ttk.Label(login_frame, text="Password:", font=("Helvetica", 16, "bold"), foreground="black")
login_password_label.pack()
login_password = ttk.Entry(login_frame, show="*", font=("Helvetica", 16))
login_password.pack()

login_button = ttk.Button(login_frame, text="Login", command=login, style="Accent.TButton")
login_button.pack(pady=10)

# Define a custom style for buttons
style.configure("Accent.TButton", foreground="black", background="#0066cc", font=("Helvetica", 14, "bold"), width=15)

root.mainloop()
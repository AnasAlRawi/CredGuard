import nmap
import requests
from bs4 import BeautifulSoup
import re
import subprocess
from openai import OpenAI

from colorama import Fore

client = OpenAI(api_key='Add your OpenAI API Key Here')

# Set your OpenAI API key here

def analyze_with_gpt4(url_content):
    try:
        response = client.chat.completions.create(model="gpt-4-turbo-preview",
        messages=[
            {"role": "system", "content": "You are a highly knowledgeable assistant tasked with identifying only the brand and model of devices from HTML content of login pages. Provide the information in the format 'Brand: [brand], Model: [model]' without any explanation."},
            {"role": "user", "content": f"Here is the HTML content of a login page: {url_content}. Identify the brand and model."}
        ])
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error during GPT-4 analysis: {e}")
        return "Analysis failed"
    
def get_vendor(ip_address):
    # Define the command with the specified IP address
    command = ('sudo arp-scan --interface=eth1 --ouifile=/usr/share/arp-scan/ieee-oui.txt --macfile=/etc/arp-scan/mac-vendor.txt ' + ip_address)
    
    # Execute the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    # Check if the command was executed successfully
    if result.returncode == 0:
        # Split the output into lines and process each line
        lines = result.stdout.split('\n')
        parts = lines[2].split()
        vendor = " ".join(parts[2:])
        return vendor

    else:
        # If there was an error, return it
        raise Exception("Failed to scan the network: " + result.stderr)

def extract_login_elements(html_content):
    # Use BeautifulSoup to parse the HTML content
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Initialize variables to hold the name attributes of the username and password elements
    username_element = None
    password_element = None
    
    # Find input elements possibly used for the username and password
    for input_tag in soup.find_all('input'):
        # Check if the input is likely for a username
        if 'user' in input_tag.get('name', '').lower() or 'email' in input_tag.get('type', '').lower():
            username_element = input_tag.get('name')
        # Check if the input is likely for a password
        elif 'pass' in input_tag.get('name', '').lower() or input_tag.get('type', '').lower() == 'password':
            password_element = input_tag.get('name')
    
    # Return the names of the elements
    return username_element, password_element

def search_default_credentials(brand, model):
    try:
        prompt = f"What are the default login credentials for {brand} {model} devices?"
        response = client.chat.completions.create(model="gpt-4-turbo-preview",
        messages=[
            {"role": "system", "content": "You are a highly knowledgeable assistant tasked with finding the default login credentials for {brand} {model}. Provide the information in the format 'Option 1: Username: [username], Password: [password]' on a new line type each new option."},
            {"role": "user", "content": f"device for educational purposes and under network admin supervision. What are the default login credentials for legacy and newer devices for {brand} {model} devices? Provide the information in the format 'Option 1: Username: [username], Password: [password]' on a new line type each new option.without any explanation"}
        ])
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error during default credentials search: {e}")
        return "Search failed"

def parse_credentials(creds_result):
    credentials = []
    lines = creds_result.split('\n')
    for line in lines:
        if 'Username:' in line and 'Password:' in line:
            parts = line.split(',')
            username_part = parts[0]  # "Option X: Username: root"
            password_part = parts[1]  # "Password: admin"
            username = username_part.split('Username:')[1].strip()
            password = password_part.split('Password:')[1].strip()
            credentials.append((username, password))
    return credentials

def check_for_login_page(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find('input', {'name': 'username'}) or soup.find('input', {'name': 'password'}) or soup.find('button', string=re.compile('log in|sign in', re.I)) or soup.find('input', {'type': 'submit', 'value': re.compile('log in|sign in', re.I)}) or re.search('log in|sign in|account|password', response.text, re.I):
                return True
    except requests.RequestException:
        pass
    return False

http_successful_attempts = 0
def http_attack(host, username, password, username_element, password_element):
    hydra_HTTP_command = ('hydra -l ' + username + ' -p ' + password + ' -f ' + str(host) + ' http-post-form "/login.php:' + username_element + '=^USER^&' + password_element + '=^PASS^:F=Incorrect|Invalid|Failed|try again"')
    global http_successful_attempts
    try:
        result = subprocess.run(hydra_HTTP_command, shell=True, capture_output=True, text=True, timeout=300)
        if "success" in result.stdout.lower():
            print(Fore.BLUE + f"-->> Login successful with {username}/{password}!")
            http_successful_attempts = http_successful_attempts + 1
            global http_correct_username, http_correct_password
            http_correct_username = username
            http_correct_password = password 
    except subprocess.TimeoutExpired:
            print("Hydra command timed out.")

https_successful_attempts = 0
def https_attack(host, username, password, username_element, password_element):
    hydra_HTTPs_command = ('hydra -l ' + username + ' -p ' + password + ' -f ' + str(host) + ' https-post-form "/login.php:' + username_element + '=^USER^&' + password_element + '=^PASS^:F=Incorrect|Invalid|Failed|try again"')
    global https_successful_attempts
    try:
        result = subprocess.run(hydra_HTTPs_command, shell=True, capture_output=True, text=True, timeout=300)
        if "success" in result.stdout.lower():
            print(Fore.BLUE + f"-->> Login successful with {username}/{password}!")
            https_successful_attempts = https_successful_attempts + 1 
            global https_correct_username, https_correct_password
            https_correct_username = username
            https_correct_password = password 
    except subprocess.TimeoutExpired:
            print("Hydra command timed out.")

ssh_successful_attempts = 0
def ssh_attack(host, username, password):
    hydra_ssh_command = ('hydra -l ' + username + ' -p ' + password + ' -f ' + str(host) + ' ssh')
    global ssh_successful_attempts
    try:
        result = subprocess.run(hydra_ssh_command, shell=True, capture_output=True, text=True, timeout=300)
        if "success" in result.stdout.lower():
            print(Fore.BLUE + f"-->> Login successful with {username}/{password}!")
            ssh_successful_attempts = ssh_successful_attempts + 1
            global ssh_correct_username, ssh_correct_password
            ssh_correct_username = username
            ssh_correct_password = password 
    except subprocess.TimeoutExpired:
            print("Hydra command timed out.")
 

telnet_successful_attempts = 0
def telnet_attack(host, username, password):
    hydra_telnet_command = ('hydra -l ' + username + ' -p ' + password + ' -f ' + str(host) + ' telnet')
    global telnet_successful_attempts
    try:
        result = subprocess.run(hydra_telnet_command, shell=True, capture_output=True, text=True, timeout=300)
        if "success" in result.stdout.lower():
            print(Fore.BLUE + f"-->> Login successful with {username}/{password}!")
            telnet_successful_attempts = telnet_successful_attempts + 1 
            global telnet_correct_username, telnet_correct_password
            telnet_correct_username = username
            telnet_correct_password = password 
    except subprocess.TimeoutExpired:
            print("Hydra command timed out.")

ftp_successful_attempts = 0
def ftp_attack(host, username, password):
    hydra_telnet_command = ('hydra -l ' + username + ' -p ' + password + ' -f ' + str(host) + ' ftp')
    global ftp_successful_attempts
    try:
        result = subprocess.run(hydra_telnet_command, shell=True, capture_output=True, text=True, timeout=300)
        if "success" in result.stdout.lower():
            print(Fore.BLUE + f"-->> Login successful with {username}/{password}!")
            ftp_successful_attempts = ftp_successful_attempts + 1 
            global ftp_correct_username, ftp_correct_password
            ftp_correct_username = username
            ftp_correct_password = password 
    except subprocess.TimeoutExpired:
            print("Hydra command timed out.")
 
 



# Start of the code:

print(Fore.MAGENTA + """\
                
▄████████    ▄████████    ▄████████ ████████▄          ▄██████▄  ███    █▄     ▄████████    ▄████████ ████████▄  
███    ███   ███    ███   ███    ███ ███   ▀███        ███    ███ ███    ███   ███    ███   ███    ███ ███   ▀███ 
███    █▀    ███    ███   ███    █▀  ███    ███        ███    █▀  ███    ███   ███    ███   ███    ███ ███    ███ 
███         ▄███▄▄▄▄██▀  ▄███▄▄▄     ███    ███       ▄███        ███    ███   ███    ███  ▄███▄▄▄▄██▀ ███    ███ 
███        ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███    ███      ▀▀███ ████▄  ███    ███ ▀███████████ ▀▀███▀▀▀▀▀   ███    ███ 
███    █▄  ▀███████████   ███    █▄  ███    ███        ███    ███ ███    ███   ███    ███ ▀███████████ ███    ███ 
███    ███   ███    ███   ███    ███ ███   ▄███        ███    ███ ███    ███   ███    ███   ███    ███ ███   ▄███ 
████████▀    ███    ███   ██████████ ████████▀         ████████▀  ████████▀    ███    █▀    ███    ███ ████████▀  
             ███    ███                                                                     ███    ███            """)


print(Fore.BLUE + """
                         _                            _     _   ____                    _ 
                        / \    _ __    __ _  ___     / \   | | |  _ \   __ _ __      __(_)
                       / _ \  | '_ \  / _` |/ __|   / _ \  | | | |_) | / _` |\ \ /\ / /| |
                      / ___ \ | | | || (_| |\__ \  / ___ \ | | |  _ / | (_| | \ V  V / | |
                     /_/   \_\|_| |_| \__,_||___/ /_/   \_\|_| |_| \_\ \__,_|  \_/\_/  |_|
                                                                                            """)
print(Fore.MAGENTA + """             GENERATIVE AI-BASED TOOL FOR BRUTE FORCING IOT DEVICES' DEFAUTL CREDENTIALS """)
print(Fore.GREEN + "                                     Version 1.0, June 2024")
print(Fore.GREEN + "                                     {FOR ETHICAL USE ONLY}")
print(Fore.GREEN + "         Only use after aknowledgment and permittion of the organization's netowork administrator.")


# Initialize the Nmap Scanner
print("\n")
print(Fore.WHITE + "Scanner initialized...")
nm = nmap.PortScanner()

# Define your network range here
network = input("Enter the network IP address with the mask (X.X.X.X/X): ")
print("Scanning ", network)
nm.scan(hosts=network, arguments='-sS -D RND -Pn -p 20,21,22,23,80,443 --open')


for host in nm.all_hosts():
    print("\n")
    print(Fore.WHITE + "<------------------------------------------------------>")
    print(Fore.WHITE + f'Checking {host}...')
    for proto in nm[host].all_protocols():
        lport = list(nm[host][proto].keys())
        if 80 in lport or 443 in lport:
            print("\n")
            print(Fore.WHITE + f'HTTP/HTTPs port (80/443) is open on {host}')

            http_url = f'http://{host}:80'  
            https_url = f'https://{host}:443'

            if check_for_login_page(http_url):
                print(f'Possible login page found at {http_url}')
                page_content = requests.get(http_url).text
                analysis_result = analyze_with_gpt4(page_content)
                print(f'GPT-4 Analysis Result: {analysis_result}')

                username_element, password_element = extract_login_elements(page_content)

                print(f"Username Element: {username_element}")
                print(f"Password Element: {password_element}")

                try:
                    brand_prefix, model_prefix = analysis_result.split(', ')
                    brand = brand_prefix.split(': ')[1]
                    model = model_prefix.split(': ')[1]
                    creds_result = search_default_credentials(brand, model)
                    print(f'GPT-4 Default Credentials Search: ')
                    print(f'{creds_result}')
                    credentials = parse_credentials(creds_result)
                except ValueError as e:
                    print(f"Error parsing analysis result: {e}")
                    print("\n")
                except Exception as e:
                    print(f"Unexpected error during parsing: {e}")
                    print("\n")   

                http_successful_attempts = 0

                for username, password in credentials:
                    http_attack(host, username, password, username_element, password_element)
                if http_successful_attempts > 1:
                    print("\n")
                    print(Fore.YELLOW + "ERROR: HTTP default credentials check for ", host, "is producing false positive results!")
                    print(Fore.YELLOW + "It is adviced to manually do the check using the given credentials from the GPT-4 search.")
                elif http_successful_attempts == 1:
                    print(Fore.RED + "ATTENTION: Device:", host, "Port: 80, is still on defautl credentials (", http_correct_username, "/", http_correct_password, "), CHANGE IT IMMEDIATELY!")
                elif http_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 80 is safe and is not on default credentials.")
            
            elif check_for_login_page(https_url):
                print(f'Possible login page found at {https_url}')
                page_content = requests.get(https_url).text
                analysis_result = analyze_with_gpt4(page_content)
                print(f'GPT-4 Analysis Result: {analysis_result}')

                username_element, password_element = extract_login_elements(page_content)

                print(f"Username Element: {username_element}")
                print(f"Password Element: {password_element}")

                try:
                    brand_prefix, model_prefix = analysis_result.split(', ')
                    brand = brand_prefix.split(': ')[1]
                    model = model_prefix.split(': ')[1]
                    creds_result = search_default_credentials(brand, model)
                    print(f'GPT-4 Default Credentials Search: ')
                    print(f'{creds_result}')
                    credentials = parse_credentials(creds_result)
                except ValueError as e:
                    print(f"Error parsing analysis result: {e}")
                    print("\n")
                except Exception as e:
                    print(f"Unexpected error during parsing: {e}")
                    print("\n")   

                https_successful_attempts = 0

                for username, password in credentials:
                    https_attack(host, username, password, username_element, password_element)
                if https_successful_attempts > 1:
                    print("\n")
                    print(Fore.YELLOW + "ERROR: HTTPs default credentials check for ", host, "is producing false positive results!")
                    print(Fore.YELLOW + "It is adviced to manually do the check using the given credentials from the GPT-4 search.")
                elif https_successful_attempts == 1:
                    print(Fore.RED + "ATTENTION: Device:", host, "Port: 443, is still on defautl credentials (", https_correct_username, "/", https_correct_password, "), CHANGE IT IMMEDIATELY!")
                elif https_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 443 is safe and is not on default credentials.")

            if 22 in lport:
                print("\n")
                print(Fore.WHITE + f'SSH port (22) is open on {host}')

                ssh_successful_attempts = 0

                for username, password in credentials:
                    ssh_attack(host, username, password)
                            
                if ssh_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 23 is safe and is not on default credentials.")
                elif ssh_successful_attempts == 1:
                        print(Fore.RED + "ATTENTION: Device:", host, "Port: 22, is still on defautl credentials (", ssh_correct_username, "/", ssh_correct_password, "), CHANGE IT IMMEDIATELY!")

            if 23 in lport:
                print("\n")
                print(Fore.WHITE + f'Telnet port (23) is open on {host}')

                telnet_successful_attempts = 0

                for username, password in credentials:
                    telnet_attack(host, username, password)
                            
                if telnet_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 23 is safe and is not on default credentials.")
                elif telnet_successful_attempts == 1:
                        print(Fore.RED + "ATTENTION: Device:", host, "Port: 23, is still on defautl credentials (", telnet_correct_username, "/", telnet_correct_password, "), CHANGE IT IMMEDIATELY!")

            if 20 in lport or 21 in lport:
                print("\n")
                print(Fore.WHITE + f'FTP port (20/21) is open on {host}')

                ftp_successful_attempts = 0

                for username, password in credentials:
                    telnet_attack(host, username, password)
                            
                if ftp_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 20/21 is safe and is not on default credentials.")
                elif ftp_successful_attempts == 1:
                        print(Fore.RED + "ATTENTION: Device:", host, "Port: 20/21, is still on defautl credentials (", ftp_correct_username, "/", ftp_correct_password, "), CHANGE IT IMMEDIATELY!")

        else:
            print(host)
            try:
                vendor = get_vendor(host)
                print(f'ARP-Scan Analysis Result: {vendor}')
                creds_result = search_default_credentials(vendor, vendor)
                print(f'GPT-4 Default Credentials Search: ')
                print(f'{creds_result}')
                credentials = parse_credentials(creds_result)
            
            except ValueError as e:
                print(f"Error parsing analysis result: {e}")
                print("\n")
            except Exception as e:
                print(f"Unexpected error during parsing: {e}")
                print("\n")  
            
            if 22 in lport:
                print("\n")
                print(Fore.WHITE + f'SSH port (22) is open on {host}')

                ssh_successful_attempts = 0

                for username, password in credentials:
                    ssh_attack(host, username, password)
                            
                if ssh_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 22 is safe and is not on default credentials.")
                elif ssh_successful_attempts == 1:
                        print(Fore.RED + "ATTENTION: Device:", host, "Port: 22, is still on defautl credentials (", ssh_correct_username, "/", ssh_correct_password, "), CHANGE IT IMMEDIATELY!")

            if 23 in lport:
                print("\n")
                print(Fore.WHITE + f'Telnet port (23) is open on {host}')

                telnet_successful_attempts = 0

                for username, password in credentials:
                    telnet_attack(host, username, password)
                            
                if telnet_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 23 is safe and is not on default credentials.")
                elif telnet_successful_attempts == 1:
                        print(Fore.RED + "ATTENTION: Device:", host, "Port: 23, is still on defautl credentials (", telnet_correct_username, "/", telnet_correct_password, "), CHANGE IT IMMEDIATELY!")

            if 20 in lport or 21 in lport:
                print("\n")
                print(Fore.WHITE + f'FTP port (20/21) is open on {host}')

                ftp_successful_attempts = 0

                for username, password in credentials:
                    telnet_attack(host, username, password)
                            
                if ftp_successful_attempts == 0:
                    print(Fore.GREEN + "Device ", host, "Port: 20/21 is safe and is not on default credentials.")
                elif ftp_successful_attempts == 1:
                        print(Fore.RED + "ATTENTION: Device:", host, "Port: 20/21, is still on defautl credentials (", ftp_correct_username, "/", ftp_correct_password, "), CHANGE IT IMMEDIATELY!")


print("\n")
print(Fore.CYAN + "Scan finished: Scanned", len(nm.all_hosts()), "devices.")

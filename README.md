This repository contains a tool that utilizes GPT-4 to analyze login pages of IoT devices and perform brute force attacks on default credentials. This tool is intended for ethical use only, under the supervision and permission of a network administrator.

## **Features**

- Scans the network for open ports using Nmap.
- Identifies login pages and extracts necessary HTML elements.
- Uses GPT-4 to identify device brands and models from login page content.
- Searches for default credentials for identified devices.
- Performs brute force attacks on HTTP, HTTPS, SSH, Telnet, and FTP services.
- Logs successful login attempts and flags devices still using default credentials.

## **Installation**

1. **Clone the repository:**
    
    ```bash
    git clone https://github.com/AnasAlRawi/CredGuard.git
    cd CredGuard
    ```
    
2. **Set up OpenAI API key:**
Add your OpenAI API key in the script where indicated.

## **Usage**

1. **Run the script:**
    
    ```bash
    sudo python3 main.py
    ```
    
2. **Enter the network IP address with the mask:**
    
    ```bash
    Enter the network IP address with the mask (X.X.X.X/X):
    ```
    
3. **Follow the on-screen instructions and monitor the output for results.**

## **Functions**

- **analyze_with_gpt4(url_content)**: Uses GPT-4 to analyze the HTML content of a login page and identify the brand and model of the device.
- **get_vendor(ip_address)**: Uses ARP-Scan to identify the vendor of a device by its IP address.
- **extract_login_elements(html_content)**: Extracts the name attributes of the username and password fields from the login page.
- **search_default_credentials(brand, model)**: Searches for the default login credentials for the identified device.
- **parse_credentials(creds_result)**: Parses the credentials returned by GPT-4.
- **check_for_login_page(url)**: Checks if the provided URL contains a login page.
- **http_attack(host, username, password, username_element, password_element)**: Performs a brute force attack on HTTP login pages.
- **https_attack(host, username, password, username_element, password_element)**: Performs a brute force attack on HTTPS login pages.
- **ssh_attack(host, username, password)**: Performs a brute force attack on SSH services.
- **telnet_attack(host, username, password)**: Performs a brute force attack on Telnet services.
- **ftp_attack(host, username, password)**: Performs a brute force attack on FTP services.

## **Disclaimer**

This tool is for educational and ethical use only. It is intended to help network administrators identify and secure devices with default credentials. Unauthorized use of this tool is prohibited and may be illegal. Always obtain permission from the network owner before scanning and testing their devices.

## **License**

This project is licensed under the MIT License. See the LICENSE file for more details.

## **Acknowledgements**

- OpenAI for providing the GPT-4 API.
- The authors of Nmap, BeautifulSoup, and other libraries used in this project.

---

Feel free to contribute to this project by submitting issues and pull requests. For major changes, please open an issue first to discuss what you would like to change.

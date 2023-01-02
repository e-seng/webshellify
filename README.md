# webshellify
A python thing to improve webshell usage

Connecting webshellify to an existing vulnerable web shell improves the user
experience when interacting with that web shell.

Webshellify provides a user a terminal emulator, allowing for command history
traversal and directory traversal. Using this, a basic terminal experience
may be used to further an attack and gain persistence on the victim.

## Usage
To properly use webshellify, some exploit funciton should be defined that
executes the command provided as the argument. This function should then return
the response data associated with the request. This output does not need to be
filtered, as Webshellify will extract any output data associated with the input
command.

```py
import Webshellify from webshellify

shell = Webshellify(exploit_function)
shell.create_shell()

def exploit_function(cmd) -> str:
  # exploit goes here ...
  return response.text
```

Calling `.create_shell()` will emulate an interactive shell that can be used to
interact with the web shell.

## Known Issues
- Some undesired behaviour during terminal emulation, particularly with some
`CTRL+KEY` inputs, or something similar
- Possibly might not maintain a web shell (consider the apache session LFI
vulnerability as used [here](https://www.hackingarticles.in/presidential-1-vulnhub-walkthrough/))

## Areas to test
- Blind code executions
- Parameter-based command injections

Current testing has been done primarily using the `vulnerables/web-dvwa` docker
container, found [here](https://github.com/opsxcq/docker-vulnerable-dvwa). The
provided `main.py` file will authorize a `PHPSESSID` cookie and spawn a
webshellify instace to use.

## Contribution
Issues and pull requests are welcome. May take some time to resolve though.

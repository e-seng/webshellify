# webshellify
A python thing to improve webshell usage

Connecting webshellify to an existing vulnerable web shell improves the user
experience when interacting with that web shell.

Webshellify provides a user a terminal emulation, allowing for command history
traversal and working directory changing. Using this, a basic terminal experience
may be used to further an attack and gain persistence on the victim.

## Usage
To properly use webshellify, the ip address or hostname of a server with an
existing web shell vulnerability along with its path must be specifed.

```py=
import Webshellify from webshellify

shell = Webshellify("http://localhost", "/path/to/webshell.php")
shell.set_method("post")

shell.set_cookie("uid", "abc123")
shell.set_body("vuln=; CMDFUZZ")

shell.create_shell()
```

Calling `create_shell()` will emulate an interactive shell that can be used to
interact with the web shell.

To properly use webshellify, it is necessary to specify a location to place the
desired commands to run. This is done by using the initial command fuzzing
keyword, `CMDFUZZ`, or by specifing a different command fuzzing keyword using
`set_fuzz_word(...)` and using that.

Fuzzing keywords may be placed within a request's query, cookie or request body
using `set_query_param(...)`, `set_cookie(...)` or `set_body(...)` respectively.

- `set_query_param(...)` accepts a key and value string, possibly with the
command fuzzing keyword
- `set_cookie(...)` accepts a key and value string, possibly with the command
fuzzing keyword
- `set_body(...)` accept a string, possibly with the command fuzzing keyword

### An important note
The headers, cookies, parameters and request bodies necessary to perform these
remote command executions still must be specified. This may be done
programmatically by passing function outputs through the provided setters.

## Known Issues
- Some undesired behaviour during terminal emulation, particularly with some
`CTRL+KEY` inputs, or something similar
- Currently not supporting command fuzzing with headers
- Possibly might not maintain a web shell (consider the apache session LFI
vulnerability as used [here](https://www.hackingarticles.in/presidential-1-vulnhub-walkthrough/))

## Areas to test
- Blind code executions
- Parameter-based 

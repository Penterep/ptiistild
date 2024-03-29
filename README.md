[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


# PTIISTILD
> IIS Tilde Enumeration Tool

## Installation

```
pip install ptiistild
```

## Add to PATH
If you cannot invoke the script in your terminal, its probably because its not in your PATH. Fix it by running commands below.

> Add to PATH for Bash
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

> Add to PATH for ZSH
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptiistild -u https://www.example.com/
ptiistild -f url_list.txt
```

## Options
```
-u   --url         <url>           Connect to URL
-f   --file        <file>          Load urls from file
-g   --grabbing                    Grab/Bruteforce all the info
-s   --specials                    Add special characters to charset [!#$%&'()@^`{}]
-p   --proxy       <proxy>         Set proxy (e.g. http://127.0.0.1:8080)
-T   --timeout     <timeout>       Set timeout (default 15)
-c   --cookie      <cookie>        Set cookie
-ua  --user-agent  <ua>            Set User-Agent
-H   --headers     <header:value>  Set custom header(s)
-t   --threads     <threads>       Set number of threads (default 20)
-C   --cache                       Cache requests (load from tmp in future)
-v   --version                     Show script version and exit
-h   --help                        Show this help message and exit
-j   --json                        Output in JSON format
```

## Dependencies
```
requests
validators
ptlibs
```

## Version History
```
1.0.2 - 1.0.3
    - Script improvements
1.0.0 - 1.0.1
    - Script improvements
    - Updated for latest ptlibs
0.0.1 - 0.0.2
    - Alpha releases
```

## License

Copyright (c) 2023 Penterep Security s.r.o.

ptiistild is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptiistild is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptiistild. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
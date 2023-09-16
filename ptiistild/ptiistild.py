#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptiistild - IIS tilde enumeration tool

    ptiistild is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptiistild is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptiistild.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import re
import time

import requests
import validators

from _version import __version__
from ptlibs import ptprinthelper, ptjsonlib, ptnethelper, ptmisclib
from ptthreads import ptthreads


class ptiistild:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.use_json    = args.json
        self.timeout     = args.timeout
        self.threads     = args.threads
        self.specials    = args.specials
        self.cache       = args.cache
        self.headers     = ptnethelper.get_request_headers(args)
        self.proxies     = {"http": args.proxy, "https": args.proxy}
        self.url_list    = self._get_urls_from_file(args.file) if args.file else args.url

        if len(self.url_list) > 1 and self.use_json:
            self.ptjsonlib.end_error("Cannot test more than 1 domain while --json parameter is present", "ERROR")

    def run(self, args):
        for url in self.url_list:
            self.url = self._adjust_url(url)
            self.result = {"files": [], "directories": [], "complete_files": []}
            self.method = self._check_vulnerable()
            if self.method and args.grabbing:
                self._grab_filenames()
                self._print_result()

        self.ptjsonlib.set_status("ok")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)

    def _check_vulnerable(self):
        """Check if site's vulnerable to IIS tilde enumeration. If vulnerable returns HTTP method that will be used for enumeration"""
        ptprinthelper.ptprint(f"Testing: {self.url}", "TITLE", not self.use_json, colortext=True)
        is_vulnerable = False
        vulnerable_methods = []
        results = {}
        for method in ["DELETE", "PUT", "POST", "GET", "PATCH", "TRACE", "DEBUG", "HEAD", "OPTIONS"]:
            ptprinthelper.ptprint(f"\r{' '*(30+len(method))}\r[*] Testing method: {method}", "INFO", not self.use_json, end=f"")

            r_1 = ptmisclib.load_url_from_web_or_temp(self.url + "*~1.*/.aspx", method, self.headers, self.proxies, None, self.timeout, False, False, self.cache, False)
            r_2 = ptmisclib.load_url_from_web_or_temp(self.url + "foo*~1.*/.aspx", method, self.headers, self.proxies, None, self.timeout, False, False, self.cache, False)
            if r_1.status_code != r_2.status_code:
                results.update({method: {"r1_status": r_1.status_code, "r2_status": r_2.status_code} })
                vulnerable_methods.append(method)
                is_vulnerable = True
                grab_method = method
                self.ok_status_code = r_1.status_code

        ptprinthelper.ptprint(f"\r{' '*100}\r\n", "", not self.use_json, end="")
        for vuln_method in results:
            self.ptjsonlib.add_vulnerability(f"enumerable_method_{vuln_method}")
            ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Different status codes for method {vuln_method} [{results[vuln_method]['r1_status']}] & [{results[vuln_method]['r2_status']}]", "INFO", self.use_json))

        ptprinthelper.ptprint(" ", " ", not self.use_json)
        ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"HTTP Header 'Server' response: {r_1.headers.get('Server', 'None')}\n", "INFO", self.use_json))
        if is_vulnerable:
            self.ptjsonlib.add_vulnerability("PTIISTILD", None, None)
            ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"{self.url} is vulnerable to IIS Tilde Enumeration", "VULN", self.use_json))
            return grab_method
        else:
            ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"{self.url} not vulnerable to IIS Tilde Enumeration", "NOTVULN", self.use_json))

    def _grab_filenames(self):
        """Grabs/Bruteforces all the information"""
        ptprinthelper.ptprint(" ", " ", not self.use_json)
        ptprinthelper.ptprint_(ptprinthelper.out_ifnot("Grabbing information", "INFO", self.use_json))
        self.targets = [char for char in "abcdefghijklmnopqrstuvwxyz0123456789()-_ "]
        self.chars = [char for char in "abcdefghijklmnopqrstuvwxyz0123456789()-_ "]
        if self.specials:
            self.chars.extend([char for char in "!#$%&'()@^`{}"])
        ptthreads_instance = ptthreads.ptthreads()
        ptthreads_instance.threads(self.targets, self._grab_thread, self.threads)

    def _grab_thread(self, target):
        """Grabbing used with threads"""
        ptprinthelper.ptprint_(ptprinthelper.out_ifnot(target, "", self.use_json), end=f"{' '*10}\r")
        if "." in target:
            extension = True
            wildcard = "*"
        else:
            extension = False
            wildcard = "*~1.*"

        if not self._check_filename(target+wildcard+"/.aspx"):
            return

        if not self._check_filename(target+wildcard[1:]+"/.aspx"):
            self._add_targets(target)
            return

        if extension:
            self._test_and_expand_file_extension(target)
        else:
            self._test_and_expand_filenames_or_directories_before_dot(target)


    def _test_and_expand_filenames_or_directories_before_dot(self, target):
        """Tests and expands names before dot character"""
        if len(target) < 6:
            self._add_targets(target)
        else:
            if self._check_filename(target+"~1"+"/.aspx"):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Directory found {target}~1 [{target}*]", "", self.use_json))
                self.result["directories"].append(target+"~1")
        self._add_targets(target + "~1.")

    def _test_and_expand_file_extension(self, target):
        """Tests the part of the filename after the dot character"""
        dot_char_index = target.find(".")
        tilde_char_index = target.find("~")
        filename_without_tilde_length = len(target[:tilde_char_index])
        extension_length = len(target[dot_char_index+1:])

        if extension_length < 3:
            ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"File found {target} [{ target.replace('~1', '*') }]", "", self.use_json))
            self._add_targets(target)
            self.result["files"].append(target)

        elif filename_without_tilde_length < 6:
            self.result["complete_files"].append(target)
            ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"File found {target} [{ target.replace('~1', '') }*]", "", self.use_json))

        else:
            ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"File found {target} [{ target.replace('~1', '*') }*]", "", self.use_json))
            self.result["files"].append(target)

    def _check_filename(self, filename):
        """Checks if filename exists on url"""
        try:
            response = requests.request(self.method, self.url+filename)
        except requests.RequestException:
            return False
        if response.status_code == self.ok_status_code:
            return True
        else:
            return False

    def _add_targets(self, target):
        """adds target+char to targets"""
        for char in self.chars:
            self.targets.append(target+char)

    def _print_result(self):
        ptprinthelper.ptprint(f"Found directories: {len(self.result['directories'])}", "TITLE", not self.use_json, newline_above=True, colortext=True)
        ptprinthelper.ptprint_(ptprinthelper.out_ifnot('\n'.join(i for i in self.result["directories"].sort()), "", self.use_json))
        ptprinthelper.ptprint(f"Found files: {len(self.result['files'])}", "TITLE", not self.use_json, newline_above=True, colortext=True)
        ptprinthelper.ptprint_(ptprinthelper.out_ifnot('\n'.join(i for i in self.result["complete_files"].sort()), "", self.use_json))
        ptprinthelper.ptprint_(ptprinthelper.out_ifnot('\n'.join(i for i in self.result["files"].sort()), "", self.use_json))


    def _adjust_url(self, url):
        if not (validators.url(url) and re.match("https?", url)):
            self.ptjsonlib.end_error("Provided URL is not in valid format", self.use_json)
        while url.endswith("/"): url = url[:1]
        url += "/"
        return url

    def _get_urls_from_file(self, filepath):
        """Return list of URls from <filepath>"""
        try:
            url_list = []
            with open(filepath, "r") as file:
                for line in file:
                    line = line.strip("\n")
                    if validators.url(line) and re.match("https?", line):
                        while line.endswith("/"): line = line[:-1]
                        line += "/"
                        url_list.append(line)
        except FileNotFoundError:
            self.ptjsonlib.end_error("File not found", self.use_json)
        return url_list


def get_help():
    return [
        {"description": ["IIS Tilde Enumeration Tool"]},
        {"usage": ["ptiistild <options>"]},
        {"usage_example": [
            "ptiisdtild -u https://www.example.com/",
            "ptiisdtild -f url_list.txt",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-f",  "--file",                   "<file>",           "Load urls from file"],
            ["-g",  "--grabbing",               "",                 "Grab/Bruteforce all the info"],
            ["-s",  "--specials",               "",                 "Add special characters to charset [!#$%&'()@^`{}]"],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",                "<timeout>",        "Set timeout (default 15)"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-ua",  "--user-agent",            "<ua>",             "Set User-Agent"],
            ["-H",  "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-t",  "--threads",                "<threads>",        "Set number of threads (default 20)"],
            ["-C",  "--cache",                  "",                 "Cache requests (load from tmp in future)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u", "--url",         type=str, nargs="+")
    parser.add_argument("-f", "--file",        type=str)
    parser.add_argument("-p", "--proxy",       type=str)
    parser.add_argument("-c", "--cookie",      type=str)
    parser.add_argument("-H", "--headers",     type=str, nargs="+")
    parser.add_argument("-ua", "--user-agent", type=str, default="Penterep Tools")
    parser.add_argument("-t", "--threads",     type=int, default=20)
    parser.add_argument("-T", "--timeout",     type=int, default=15)
    parser.add_argument("-C", "--cache",       action="store_true")
    parser.add_argument("-s", "--specials",    action="store_true")
    parser.add_argument("-g", "--grabbing",    action="store_true")
    parser.add_argument("-j", "--json",        action="store_true")
    parser.add_argument("-v", "--version",     action="version", version=f"%(prog)s {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptiistild"
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    args = parse_args()
    script = ptiistild(args)
    script.run(args)


if __name__ == "__main__":
    main()

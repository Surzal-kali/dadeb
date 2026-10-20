
import os
import shlex
import shutil
import subprocess
from constants import framework_tool

# Canonical ExploitDB install locations. searchsploit is shipped as a single
# shell script under /opt/exploitdb on Kali/Parrot and similar. /usr/local/bin
# symlinks to it, and since /usr/local/bin is on sudo's secure_path,
# shutil.which("searchsploit") resolves it even when the framework runs as
# root. We still hard-code /opt/exploitdb/searchsploit as a fallback for boxes
# that lack the symlink (or where it has been removed/broken again), so a bare
# subprocess.run never raises FileNotFoundError. (See bootstrap.py's .env
# loading note about the same sudo env-stripping situation.)
_SEARCHSPLOIT_CANDIDATES = (
    "/opt/exploitdb/searchsploit",
    "/usr/local/bin/searchsploit",
    "/usr/bin/searchsploit",
)


def _resolve_searchsploit():
    """Locate the searchsploit binary, or return None if not installed."""
    found = shutil.which("searchsploit")
    if found and os.access(found, os.X_OK):
        return found
    for cand in _SEARCHSPLOIT_CANDIDATES:
        # os.path.exists follows symlinks; reject broken symlinks (e.g. the
        # /opt/expldb typo) so we don't hand subprocess a dangling path.
        if os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    return None


#this module will be our primary searchsploit module, it will be used to search for exploits using the local searchsploit CLI.
@framework_tool(
    "Look up known exploits for a vulnerability or service using the local "
    "searchsploit CLI (ExploitDB). Pass keywords (e.g. 'apache 2.4' or "
    "'vsftpd backdoor') and get matching ExploitDB entries back.",
    next_hints=["index_modules (find matching Metasploit modules)"],
)
def search_exploit(query):
    # Use searchsploit command line tool to search for exploits.
    #
    # searchsploit treats each argv as a separate search term combined with AND
    # (see https://www.exploit-db.com/searchsploit: "term1 [term2] ... [termN]").
    # Passing the whole `query` as a single argument would search for the literal
    # string "apache 2.4" instead of "apache" AND "2.4", yielding no results.
    # shlex.split respects quoted sub-phrases a caller may want kept literal.
    #
    # --disable-colour keeps ANSI escape codes out of the captured stdout so the
    # framework/secretary can parse and relay the text cleanly.
    try:
        terms = shlex.split(query) if isinstance(query, str) else list(query)
        if not terms:
            return "Error: empty search query"
        binary = _resolve_searchsploit()
        if not binary:
            return ("Error: searchsploit not found. Install exploitdb "
                    "(apt install exploitdb) or ensure /opt/exploitdb/searchsploit "
                    "is executable and on PATH.")
        result = subprocess.run(
            [binary, '--disable-colour', *terms],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"

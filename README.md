# PoSH script using VT's apiv3

Starting point for using PoSH for Virustotal using the v3 endpoint. May not be the most elegant code or the most efficient code, but it gets the job done. The initial script is just returning the last analysis information. Goal is to slowly add on to this base script. Hope it helps someone.

Basic use of this script is via arguments passed to it. For example:
- Searching IP(s): vt.ps1 -ip [ip1],[ip2],[ipN]
- Searching Domain (only supports just one value at this time): vt.ps1 -domain [domain1]
- Searching Hash (only supports just one value at this time): vt.ps1 -hash [hash1]

Jan 28, 2023 Update
- Added support for multiple IPs as comma seperated values.
- Did more formatting of the text for readability.

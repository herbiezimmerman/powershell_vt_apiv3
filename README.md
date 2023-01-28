# PoSH script using VT's apiv3

Starting point for using PoSH for Virustotal using the v3 endpoint. May not be the most elegant code or the most efficient code, but it gets the job done. The initial script is just returning the last analysis information. Goal is to slowly add on to this base script. Hope it helps someone.

Basic use of this script is via arguments passed to it. For example:
- Searching IP(s): vt.ps1 -ip <ip1>,<ip2>,<ipN>
- Searching Domain(s): vt.ps1 -ip <domain1>,<domain2>,<domainN>
- Searching Hash(es): vt.ps1 -ip <hash1>,<hash2>,<hashN>

Jan 28, 2023 Update
- Added support for multiple IPs as comma seperated values.
- Did more formatting of the text for readability.

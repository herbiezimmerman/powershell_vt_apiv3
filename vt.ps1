[CmdletBinding()]
    param (
        [Parameter(Mandatory=$False,ParameterSetName = 'ip')][string]$ip,
        [Parameter(Mandatory=$False,ParameterSetName = 'domain')][string]$domain,
        [Parameter(Mandatory=$False,ParameterSetName = 'hash')][string]$hash
    )

#Set up proxy auth
$pxyauth = new-object System.Net.WebClient
$pxyauth.Headers.Add("user-agent", "Powershell Script")
$pxyauth.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

#Set APIKey
$token = Get-Content <path to file with VT API key>

if ($PSCmdlet.ParameterSetName -eq 'ip') {
    #Set URL with IOC
    $final_uri = "https://www.virustotal.com/api/v3/search?query=$ip"
    
    #Create Splat
        $ipParams = @{
        "Uri" = $final_uri
           "Method" = 'GET'
           "Headers" = @{
                 "Content-Type" = 'application/json'
                 "x-apikey" = $token
           }}
    
    $response = Invoke-RestMethod @ipParams
    $response.data.attributes.last_analysis_results
}

elseif ($PSCmdlet.ParameterSetName -eq 'domain') {
    #Set URL with IOC
    $final_uri = "https://www.virustotal.com/api/v3/search?query=$domain"

    #Create Splat
        $domainParams = @{
        "Uri" = $final_uri
           "Method" = 'GET'
           "Headers" = @{
                 "Content-Type" = 'application/json'
                 "x-apikey" = $token
           }}

    $response = Invoke-RestMethod @domainParams
    $response.data.attributes.last_analysis_results
}

elseif ($PSCmdlet.ParameterSetName -eq 'hash') {
    #Set URL with IOC
    $final_uri = "https://www.virustotal.com/api/v3/search?query=$hash"

    #Create Splat
        $hashParams = @{
        "Uri" = $final_uri
           "Method" = 'GET'
           "Headers" = @{
                 "Content-Type" = 'application/json'
                 "x-apikey" = $token
           }}

    $response = Invoke-RestMethod @hashParams
    $response.data.attributes.last_analysis_results
}

else {
    write-host("Invalid input. Script will exit now")
    exit}

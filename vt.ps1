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
$token = Get-Content "< path to key file >"

if ($PSCmdlet.ParameterSetName -eq 'ip') {
    #Set URL with IOC
    $final_uri = "https://www.virustotal.com/api/v3/search?query=$ip"
    $final_uri_ip_resolutions = "https://www.virustotal.com/api/v3/ip_addresses/$ip/resolutions?limit=10"
    
    #Create Base IP Splat
        $ipParams = @{
        "Uri" = $final_uri
           "Method" = 'GET'
           "Headers" = @{
                 "Content-Type" = 'application/json'
                 "x-apikey" = $token
           }}

    #Create IP Resolutions Splat
        $ip_resParams = @{
        "Uri" = $final_uri_ip_resolutions
           "Method" = 'GET'
           "Headers" = @{
                 "Content-Type" = 'application/json'
                 "x-apikey" = $token
           }}
    

    #Formatting for base IP query
    $ip_base_response = Invoke-RestMethod @ipParams
    $response_as_owner = $ip_base_response.data.attributes.as_owner | out-string
    $response_tags = $ip_base_response.data.attributes.tags| out-string
    $response_last_analysis_stats = $ip_base_response.data.attributes.last_analysis_stats| out-string
    $response_last_analysis_results = $ip_base_response.data.attributes.last_analysis_results.psobject.Properties.value | Where { $_.result -notlike 'clean' -and $_.result -notlike 'unrated'  } | out-string

    write-host ''
    write-host ''

    write-host -ForegroundColor Yellow '< Virustotal URL>'
    write-host "https://www.virustotal.com/gui/ip-address/$ip"
    write-host ''

    write-host -ForegroundColor Yellow '< ASN Owner >'
    $response_as_owner.trim()
    write-host ''

    write-host -ForegroundColor Yellow '< Tags >'
    if ([string]::IsNullOrEmpty($response_tags)){
        write-host -ForegroundColor Red 'NA' }
    else {
        $response_tags}
    write-host ''
    
    write-host -ForegroundColor Yellow '< Last Analysis Stats >'
    $response_last_analysis_stats.trim()
    write-host ''
    
    write-host -ForegroundColor Yellow '< Last Analysis Results (excluding CLEAN/UNRATED) >'
    $response_last_analysis_results.trim()
    write-host ''

    write-host -ForegroundColor Yellow '< Passive DNS (limit of 10 results >'

    #Formatting for IP resolutions query
    $ip_resolutions = Invoke-RestMethod @ip_resParams
    for ($array_length_counter = 0; $array_length_counter -lt $ip_resolutions.meta.count; $array_length_counter++) {

        write-host "Date of analysis: " (([System.DateTimeOffset]::FromUnixTimeSeconds($ip_resolutions.data.attributes.date[$array_length_counter])).DateTime).ToString()
        
        $string_ip_hostname =  $ip_resolutions.data.attributes.host_name[$array_length_counter] | out-string
        write-host -ForegroundColor Magenta '< Hostname >'
        write-host $string_ip_hostname.trim()
        write-host ''

        $string_ip_last_analysis_stats_ip = $ip_resolutions.data.attributes.ip_address_last_analysis_stats[$array_length_counter] | out-string
        write-host -ForegroundColor Magenta '< Last IP Analysis Stats >'
        write-host $string_ip_last_analysis_stats_ip.trim()
        write-host ''

        $string_ip_last_analysis_stats_hostname = $ip_resolutions.data.attributes.host_name_last_analysis_stats[$array_length_counter] | out-string
        write-host -ForegroundColor Magenta '< Last Hostname Analysis Stats >'
        write-host $string_ip_last_analysis_stats_hostname.trim()
        write-host ''
        write-host '-------------------------------------------------'

    }

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
    write-host -ForegroundColor Yellow 'Invalid input. Script will exit now'
    exit}

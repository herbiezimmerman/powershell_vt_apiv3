[CmdletBinding()]
param (
    [Parameter(Mandatory=$False, ParameterSetName='ip')]
    [string[]]$ip,

    [Parameter(Mandatory=$False, ParameterSetName='domain')]
    [string[]]$domain,

    [Parameter(Mandatory=$False, ParameterSetName='hash')]
    [string[]]$hash
)

# Initialize the array to store results for each domain
$results = @()

#Set up proxy auth
$pxyauth = new-object System.Net.WebClient
$pxyauth.Headers.Add("user-agent", "Powershell Script")
$pxyauth.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

#Set APIKey
$token = Get-Content "< path to key file >"

#Section for IP(s) search
if ($PSCmdlet.ParameterSetName -eq 'ip')
{
    write-host ''
    #For loop to deal with single/multiple IP arguments
    for ($ip_array = 0; $ip_array -lt $ip.count; $ip_array++) 
    {
        
        $temp_array_ip = $ip[$ip_array]                                      
        $final_uri = "https://www.virustotal.com/api/v3/search?query=$temp_array_ip"
        $final_uri_ip_resolutions = "https://www.virustotal.com/api/v3/ip_addresses/$temp_array_ip/resolutions"
        
        #Create base IP search splat
            $ipParams = @{
            "Uri" = $final_uri
               "Method" = 'GET'
               "Headers" = @{
                     "Content-Type" = 'application/json'
                     "x-apikey" = $token
            }}
        
        #Create IP resolutions search splat
            $ip_resParams = @{
            "Uri" = $final_uri_ip_resolutions
               "Method" = 'GET'
               "Headers" = @{
                     "Content-Type" = 'application/json'
                     "x-apikey" = $token
            }}
        
        #Rest API calls
        $ip_base_response = Invoke-RestMethod @ipParams
        $ip_resolutions = Invoke-RestMethod @ip_resParams

        $response_as_owner = $ip_base_response.data.attributes.as_owner | out-string
        $response_tags = $ip_base_response.data.attributes.tags | out-string
        $response_last_analysis_stats = $ip_base_response.data.attributes.last_analysis_stats | out-string
        $response_last_analysis_results = $ip_base_response.data.attributes.last_analysis_results.psobject.Properties.value | Where { $_.result -notlike 'clean' -and $_.result -notlike 'unrated'  } | out-string      
    
        write-host -ForegroundColor Blue '< Virustotal URL>'
        write-host "https://www.virustotal.com/gui/ip-address/$temp_array_ip"
        write-host '-------------------------------------------------'
        write-host ''
        
        write-host -ForegroundColor Yellow '< ASN Owner >'
        $response_as_owner.trim()
        write-host '-------------------------------------------------' 
        write-host ''
        
        write-host -ForegroundColor Yellow '< Tags >'
        if ([string]::IsNullOrEmpty($response_tags)) { write-host -ForegroundColor Red 'NA' }
        else { $response_tags }
        write-host '-------------------------------------------------' 
        write-host ''
                
        write-host -ForegroundColor Yellow '< Last Analysis Stats >'
        $response_last_analysis_stats.trim()
        write-host '-------------------------------------------------' 
        write-host ''
                
        write-host -ForegroundColor Yellow '< Last Analysis Results (excluding CLEAN/UNRATED) >'
        $response_last_analysis_results.trim()
        write-host '-------------------------------------------------' 
        write-host ''

        write-host -ForegroundColor Yellow "< Passive DNS For IP $($ip[$ip_array]) >" #The $($ip[$ip_array]) syntax is to have whole expression eval'ed. W/o it then only var is eval'ed.
        if ([string]::IsNullOrEmpty($ip_resolutions.data[$ip_array])) { 
            write-host -ForegroundColor Red 'NA'
            write-host '-------------------------------------------------'
            write-host ''
        }
    
        #Formatting for IP resolutions/passive DNS query
        $ip_resolutions = Invoke-RestMethod @ip_resParams

        for ($array_length_counter = 0; $array_length_counter -lt $ip_resolutions.meta.count; $array_length_counter++)
        {
            write-host "Date of analysis:" (([System.DateTimeOffset]::FromUnixTimeSeconds($ip_resolutions.data.attributes.date[$array_length_counter])).DateTime).ToString('yyyy-MM-dd HH:mm:ss')
            $string_ip_hostname = $ip_resolutions.data.attributes.host_name[$array_length_counter] | out-string
            write-host "Hostname:" $string_ip_hostname.trim()
            write-host ''
    
            $string_ip_last_analysis_stats_hostname = $ip_resolutions.data.attributes.host_name_last_analysis_stats[$array_length_counter] | out-string
            write-host -ForegroundColor Magenta '< Last Hostname Analysis Stats >'
            write-host $string_ip_last_analysis_stats_hostname.trim()
            write-host '-------------------------------------------------'  
            write-host ''
             
        }
    }
}

elseif ($PSCmdlet.ParameterSetName -eq 'domain') {
    foreach ($d in $domain) {
        #Set URL with IOC
        $final_uri = "https://www.virustotal.com/api/v3/search?query=$d"

        #Create Splat
        $domainParams = @{
            "Uri" = $final_uri
            "Method" = 'GET'
            "Headers" = @{
                "Content-Type" = 'application/json'
                "x-apikey" = $token
            }
        }

        $response = Invoke-RestMethod @domainParams

        # Create a custom object to store the results for each domain
        $domainResult = [PSCustomObject]@{
            Domain = $d
            LastAnalysisResults = $response.data.attributes.last_analysis_results
            # Add more properties as needed
        }

        # Add the custom object to the $results array
        $results += $domainResult
    }
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

# Function to write text in bold
function Write-BoldText {
    param (
        [string]$Text
    )
    $color = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = 'Green'
    Write-Host $Text
    $host.UI.RawUI.ForegroundColor = $color
}

# Display results for each domain
foreach ($result in $results) {
    Write-BoldText "Results for domain: $($result.Domain)"
    Write-Host '-------------------------------------------------'

    if ($result.LastAnalysisResults.Count -eq 0) {
        Write-Host "No analysis results available for this domain."
    }
    else {
        foreach ($analysis in $result.LastAnalysisResults.PSObject.Properties) {
            $vendor = $analysis.Name
            $resultInfo = $analysis.Value

            Write-Host "Vendor: $vendor"
            Write-Host "Category: $($resultInfo.Category)"
            Write-Host "Result: $($resultInfo.Result)"
            Write-Host "Method: $($resultInfo.Method)"
            Write-Host '-------------------------------------------------'
        }
    }
    
    Write-Host ''
}
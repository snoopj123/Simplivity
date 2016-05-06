Import-Module VMware.VimAutomation.Core

Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

function Get-AccessToken
{
    param([string]$IP)
    process
    {
        $url = "https://" + $IP + "/api/oauth/token"
        $base64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::UTF8.GetBytes("simplivity:"))
        $cred = Get-Credential
        $username = $cred.UserName
        $pass_word = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))
        $body = @{username="$username";password="$pass_word";grant_type="password"}
        $headers = @{}
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Accept", "application/json")
        $ret_token = Invoke-RestMethod -Uri $url -Headers $headers -Body $body -Method Post
        $global:IPAddress = $IP
        $global:Token = $ret_token.access_token
    }
}

function Get-OmniVM([string]$VMName)
{
    $url = "https://" + $IPAddress + "/api/virtual_machines"
    $header = @{}
    $header.Add("Authorization", "Bearer $Token")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("show_optional_fields", "false")
    $body.Add("name", "$VMName")
    $result = Invoke-RestMethod -Uri $url -Headers $header -Body $body -Method Get
    return $result.virtual_machines.id
    #return $result
}

function Clone-OmniVM
{
    param(
    [Parameter(ValueFromPipeline=$true)][string]$VM,
    [string]$VMName)
    process
    {
        $url = "https://" + $IPAddress + "/api/virtual_machines/" + $_ + "/clone"
        $header = @{}
        $header.Add("Authorization", "Bearer $Token")
        $header.Add("Accept", "application/json")
        $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
        $body = @{}
        $body.Add("app_consistent", "false")
        $body.Add("virtual_machine_name", "$VMName")
        $body = $body | ConvertTo-Json
        $result = Invoke-RestMethod -Uri $url -Headers $header -Body $body -Method Post
        #return $result.task.id
        return $result
    }
}

# -----------------
#  MAIN SCRIPT BODY
# -----------------

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Get-AccessToken -IP 10.20.4.145

$test = Get-OmniVM -VMName Jon1 | Clone-OmniVM -VMName Jon54321

#$test = Get-OmniVM -VMName Jon1
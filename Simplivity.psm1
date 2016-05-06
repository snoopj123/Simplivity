function Connect-OmniStack
{
<#

#>
    [CmdletBinding()][OutputType('System.Management.Automation.PSObject')]

    param(
    [parameter(Mandatory=$true,ParameterSetName="Server")]
    [ValidateNotNullOrEmpty()]
    [String]$Server,

    [parameter(Mandatory=$false)]
    [switch]$IgnoreCertRequirements
    )

    if ($PSBoundParameters.ContainsKey("IgnoreCertRequirements"))
    {
        if ( -not ("TrustAllCertsPolicy" -as [type]))
        {
            Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy
            {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem)
                    {  return true; }
            }
"@
        }
    
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $SignedCertificates = $false
    }
    else { $SignedCertificates = $true }

    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $cred = Get-Credential
    $username = $cred.UserName
    $pass_word = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))
    $uri = "https://" + $Server + "/api/oauth/token"
    $base64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::UTF8.GetBytes("simplivity:"))
    $body = @{username="$username";password="$pass_word";grant_type="password"}
    $headers = @{}
    $headers.Add("Authorization", "Basic $base64")
    $headers.Add("Accept", "application/json")
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Body $body -Method Post

    $Global:OmniStackConnection = [pscustomobject]@{
        Server = "https://$($Server)"
        Username = $username
        Token = $response.access_token
        SignedCertificates = $SignedCertificates
    }

}

function Get-OmniStackVM
{
<#

#>

    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$true,ParameterSetName="VMName")]
    [string]$VMName
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("show_optional_fields", "false")
    $body.Add("name", "$VMName")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    $omniVM = @()
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $response.virtual_machines.id
    $c | Add-Member -Type NoteProperty -Name Name -Value $response.virtual_machines.name
    $c | Add-Member -Type NoteProperty -Name State -Value $response.virtual_machines.state
    $c | Add-Member -Type NoteProperty -Name CreatedAt -Value $response.virtual_machines.created_at
    $c | Add-Member -Type NoteProperty -Name DatastoreID -Value $response.virtual_machines.datastore_id
    $c | Add-Member -Type NoteProperty -Name DatastoreName -Value $response.virtual_machines.datastore_name
    $c | Add-Member -Type NoteProperty -Name PolicyID -Value $response.virtual_machines.policy_id
    $c | Add-Member -Type NoteProperty -Name PolicyName -Value $response.virtual_machines.policy_name
    $c | Add-Member -Type NoteProperty -Name HypervisorID -Value $response.virtual_machines.hypervisor_object_id
    $c | Add-Member -Type NoteProperty -Name OmniStackClusterID -Value $response.virtual_machines.omnistack_cluster_id
    $c | Add-Member -Type NoteProperty -Name OmniStackClusterName -Value $response.virtual_machines.omnistack_cluster_name
    $omniVM += $c
    $omniVM | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.VirtualMachine") }

    return $omniVM
}
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
    [switch]$IgnoreCertReqs
    )

    if ($PSBoundParameters.ContainsKey("IgnoreCertReqs"))
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
        Refresh = $response.refresh_token
        SignedCertificates = $SignedCertificates
        #Credential = $cred
    }
}

function Get-OmniStackVM
{
<#

#>

    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$Name
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("show_optional_fields", "false")
    $body.Add("name", "$Name")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    $omniVM = @()
    foreach ($vm in $response.virtual_machines)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $vm.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $vm.name
        $c | Add-Member -Type NoteProperty -Name State -Value $vm.state
        $c | Add-Member -Type NoteProperty -Name CreatedAt -Value $vm.created_at
        $c | Add-Member -Type NoteProperty -Name DatastoreID -Value $vm.datastore_id
        $c | Add-Member -Type NoteProperty -Name DatastoreName -Value $vm.datastore_name
        $c | Add-Member -Type NoteProperty -Name PolicyID -Value $vm.policy_id
        $c | Add-Member -Type NoteProperty -Name PolicyName -Value $vm.policy_name
        $c | Add-Member -Type NoteProperty -Name HypervisorID -Value $vm.hypervisor_object_id
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterID -Value $vm.omnistack_cluster_id
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterName -Value $vm.omnistack_cluster_name
        $omniVM += $c
    }
    $omniVM | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.VirtualMachine") }

    return $omniVM
}

function Copy-OmniStackVM
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [psobject]$VM,
    [Parameter(Mandatory=$true,ParameterSetName="Name")]
    [string]$Name
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $($VM.ID) + "/clone"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("app_consistent", "false")
    $body.Add("virtual_machine_name", "$Name")
    $body = $body | ConvertTo-Json
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Post
    $omniTask = @()
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $response.task.id
    $c | Add-Member -Type NoteProperty -Name State -Value $response.task.state
    $c | Add-Member -Type NoteProperty -Name AffectedObjects -Value $response.task.affected_objects
    $c | Add-Member -Type NoteProperty -Name ErrorCode -Value $response.task.error_code
    $c | Add-Member -Type NoteProperty -Name StartTime -Value $response.task.start_time
    $c | Add-Member -Type NoteProperty -Name EndTime -Value $response.task.end_time
    $omniTask += $c
    $omniTask | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Task") }

    return $omniTask
}

function Get-OmniStackTask
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [psobject]$Task
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/tasks/" + $($Task.ID)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
    $omniTask = @()
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $response.task.id
    $c | Add-Member -Type NoteProperty -Name State -Value $response.task.state
    $c | Add-Member -Type NoteProperty -Name AffectedObjects -Value $response.task.affected_objects
    $c | Add-Member -Type NoteProperty -Name ErrorCode -Value $response.task.error_code
    $c | Add-Member -Type NoteProperty -Name StartTime -Value $response.task.start_time
    $c | Add-Member -Type NoteProperty -Name EndTime -Value $response.task.end_time
    $omniTask += $c
    $omniTask | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Task") }

    return $omniTask
}

function Redo-OmniStackToken
{
<#
#>

    $uri = $($Global:OmniStackConnection.Server) + "/api/oauth/token"
    $body = @{grant_type="refresh_token";refresh_token="$($Global:OmniStackConnection.Refresh)"}
    $base64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::UTF8.GetBytes("simplivity:"))
    $headers = @{}
    $headers.Add("Authorization", "Basic $base64")
    $headers.Add("Accept", "application/json")

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Body $body -Method Post

    $Global:OmniStackConnection.Token = $response.access_token
}
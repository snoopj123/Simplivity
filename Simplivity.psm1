<#
-----------------------------------------------------------------------------
GENERAL FUNCTIONS
-----------------------------------------------------------------------------
#>
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
    $cred = $host.ui.PromptForCredential("Enter in your OmniStack Credentials", "Enter in your username & password.", "", "")
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
    }
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

<#
-----------------------------------------------------------------------------
VIRTUAL MACHINE FUNCTIONS
-----------------------------------------------------------------------------
#>

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

    try
    {
        $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    }
    catch
    {
        if ($_.Exception.Message -match "401")
        {   
            Redo-OmniStackToken
            $header.Remove("Authorization")
            $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
            $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
        }
    }
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

function Move-OmniStackVM
{
<#
#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [psobject]$VM,
    [Parameter(Mandatory=$false,ParameterSetName="NewName")]
    [string]$NewName,
    [Parameter(Mandatory=$true,ParameterSetName="DestinationDatastore")]
    [string]$DestinationDatastore
    )
	
	$VM = $VM | where {$_.State -eq "ALIVE"}

    $DestinationDS = Get-OmniStackDatastores | where {$_.Name -eq $DestinationDatastore}

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $($VM.ID) + "/move"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("virtual_machine_name", "$NewName")
    $body.Add("destination_datastore_id", $DestinationDS.Id)
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

function Set-OmniStackVMBackupPolicy
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$Name,
	
	[Parameter(Mandatory=$false,ValueFromPipeline=$true,ParameterSetName="Name")]
    [psobject]$VM,
	
    [Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="PolicyName")]
    [string]$PolicyName
    )

    $PolicyIDTemp = Get-OmniStackBackupPolicy -PolicyName $PolicyName
	$PolicyID = $PolicyIDTemp.ID
	
	if ($vm -eq $null) {
	$vm = Get-OmniStackVM -Name $Name
	}

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $($VM.ID) + "/set_policy"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("policy_id", "$PolicyID")
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

function Get-OmniStackVMBackups
{
<#

#>

    [CmdletBinding()]
    param(
	
	[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
    [psobject]$VM,
	
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$Name
    )

    $DestinationClusterTemp = Get-OmniStackClusters | where {$_.Name -eq $DestinationCluster}
	$DestinationClusterID = $DestinationClusterTemp.Id
	
	if ($vm -eq $null) {
	$vm = Get-OmniStackVM -Name $Name
	}

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $($VM.ID) + "/backups"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body = $body | ConvertTo-Json
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
    $omniBackups = @()
    foreach ($Backup in $response.backups)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $Backup.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $Backup.name
        $c | Add-Member -Type NoteProperty -Name VirtualMachineID -Value $Backup.virtual_machine_id
        $c | Add-Member -Type NoteProperty -Name VirtualMachineName -Value $Backup.virtual_machine_name
        $c | Add-Member -Type NoteProperty -Name State -Value $Backup.state
        $c | Add-Member -Type NoteProperty -Name CreatedAt -Value $Backup.created_at
        $c | Add-Member -Type NoteProperty -Name DatastoreID -Value $Backup.datastore_id
        $c | Add-Member -Type NoteProperty -Name DatastoreName -Value $Backup.datastore_name
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterID -Value $Backup.omnistack_cluster_id
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterName -Value $Backup.omnistack_cluster_name
        $omniBackups += $c
    }
    $omniBackups | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Backup") }

    return $omniBackups
}


<#
-----------------------------------------------------------------------------
DATASTORE FUNCTIONS
-----------------------------------------------------------------------------
#>

function Get-OmniStackDatastores
{
<#
#>

    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$Name
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/datastores"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("show_optional_fields", "false")
    $body.Add("name", "$Name")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    $omniDS = @()
    foreach ($DS in $response.datastores)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $DS.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $DS.name
        $c | Add-Member -Type NoteProperty -Name Size -Value $DS.Size
        $c | Add-Member -Type NoteProperty -Name CreatedAt -Value $DS.created_at
        $c | Add-Member -Type NoteProperty -Name PolicyID -Value $DS.policy_id
        $c | Add-Member -Type NoteProperty -Name PolicyName -Value $DS.policy_name
        $c | Add-Member -Type NoteProperty -Name HypervisorID -Value $DS.hypervisor_object_id
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterID -Value $DS.omnistack_cluster_id
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterName -Value $DS.omnistack_cluster_name
        $omniDS += $c
    }
    $omniDS | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Datastore") }

    return $omniDS
}

function Get-OmniStackDatastore
{
<#
#>
    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$false)]
    [String]$Name
    )
	
	$DatastoreTemp = Get-OmniStackDatastores | where {$_.Name -eq $Name}
	$DatastoreID = $DatastoreTemp.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/datastores/" + $($DatastoreID)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
	
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
    $omniDatastore = @()
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $response.datastore.id
    $c | Add-Member -Type NoteProperty -Name Name -Value $response.datastore.name
    $c | Add-Member -Type NoteProperty -Name Deleted -Value $response.datastore.deleted
    $c | Add-Member -Type NoteProperty -Name Size -Value $response.datastore.size
    $c | Add-Member -Type NoteProperty -Name Shares -Value $response.datastore.shares
    $c | Add-Member -Type NoteProperty -Name ClusterID -Value $response.datastore.omnistack_cluster_id
    $c | Add-Member -Type NoteProperty -Name ClusterName -Value $response.datastore.omnistack_cluster_name
    $c | Add-Member -Type NoteProperty -Name CreatedAt -Value $response.datastore.created_at
    $c | Add-Member -Type NoteProperty -Name PolicyID -Value $response.datastore.policy_id
    $c | Add-Member -Type NoteProperty -Name PolicyName -Value $response.datastore.policy_name
    $c | Add-Member -Type NoteProperty -Name MountDirectory -Value $response.datastore.mount_directory
    $c | Add-Member -Type NoteProperty -Name HypervisorObjID -Value $response.datastore.hypervisor_object_id
    $omniDatastore += $c
    $omniDatastore | % {$_.PSObject.TypeNames.Insert(0,"Simplivity.Datastore") }

    return $omniDatastore
}

function New-OmniStackDatastore
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true,ParameterSetName="Name")]
    [string]$Name,
    
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="SizeinGB")]
    [Int32]$SizeinGB,
	
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="PolicyName")]
    [string]$PolicyName,
	
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="ClusterName")]
    [string]$ClusterName
    )

    $ClusterTemp = Get-OmniStackClusters | where {$_.Name -eq $ClusterName}
	$ClusterID = $ClusterTemp.Id
	
	$PolicyTemp = Get-OmniStackBackupPolicy -PolicyName $PolicyName
	$PolicyID = $PolicyTemp.Id
	
	[double]$Size = $SizeinGB * 1073741824
    
	$uri = $($Global:OmniStackConnection.Server) + "/api/datastores"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("name", $Name)
    $body.Add("omnistack_cluster_id", $ClusterID)
	$body.Add("size", $Size)
	$body.Add("policy_id", $PolicyID)
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

function Remove-OmniStackDatastore
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false,ParameterSetName="DatastoreName")]
    [string]$DatastoreName,
	[Parameter(ValueFromPipeline=$true,ParameterSetName="DatastoreName")]
    [psobject]$Datastore
    )

	if ($DatastoreName -ne $null -and $DatastoreName -ne "") {
		$Datastore = Get-OmniStackDatastore -Name $DatastoreName
	}
	
	$DatastoreID = $Datastore.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/datastores/" + $($DatastoreID)
	
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method DELETE
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

function Resize-OmniStackDatastore
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(ValueFromPipeline=$true,ParameterSetName="Name")]
    [psobject]$Datastore,	
    [Parameter(ParameterSetName="Name")]
	[Parameter(ParameterSetName="DatastoreName")]
    [string]$DatastoreName,
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="Size")]
    [single]$SizeinGB
	)
	
	if ($DatastoreName -ne $null -and $DatastoreName -ne "") {
		$Datastore = Get-OmniStackDatastore -Name $DatastoreName
	}
	
	$DatastoreID = $Datastore.Id
	
	[double]$Size = $SizeinGB * 1073741824

    $uri = $($Global:OmniStackConnection.Server) + "/api/datastores/" + $($DatastoreID) + "/resize"
	
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
	$body = @{}
	$body.Add("size", $Size)
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

function Set-OmniStackDatastoreBackupPolicy
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$DatastoreName,
	[Parameter(Mandatory=$false,ValueFromPipeline=$true,ParameterSetName="Name")]
    [psobject]$Datastore,
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="Policy")]
    [String]$PolicyName
	)

	if ($DatastoreName -ne $null -and $DatastoreName -ne "") {
		$Datastore = Get-OmniStackDatastore -Name $DatastoreName
	}
	
	$DatastoreID = $Datastore.Id
	
	$PolicyTemp = Get-OmniStackBackupPolicy -PolicyName $PolicyName
	$PolicyID = $PolicyTemp.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/datastores/" + $($DatastoreID) + "/set_policy"
	
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
	$body = @{}
	$body.Add("policy_id", $PolicyID)
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

<#
-----------------------------------------------------------------------------
TASK FUNCTIONS
-----------------------------------------------------------------------------
#>

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


<#
-----------------------------------------------------------------------------
BACKUP FUNCTIONS
-----------------------------------------------------------------------------
#>

function Get-OmniStackBackups
{
<#

#>

    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$false,ParameterSetName="BackupName")]
    [string]$BackupName
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/backups"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("name", "$BackupName")

    try
    {
        $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    }
    catch
    {
        if ($_.Exception.Message -match "401")
        {   
            Redo-OmniStackToken
            $header.Remove("Authorization")
            $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
            $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
        }
    }
    $omniBackups = @()
    foreach ($Backup in $response.backups)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $Backup.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $Backup.name
        $c | Add-Member -Type NoteProperty -Name VirtualMachineID -Value $Backup.virtual_machine_id
        $c | Add-Member -Type NoteProperty -Name VirtualMachineName -Value $Backup.virtual_machine_name
        $c | Add-Member -Type NoteProperty -Name State -Value $Backup.state
        $c | Add-Member -Type NoteProperty -Name CreatedAt -Value $Backup.created_at
        $c | Add-Member -Type NoteProperty -Name DatastoreID -Value $Backup.datastore_id
        $c | Add-Member -Type NoteProperty -Name DatastoreName -Value $Backup.datastore_name
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterID -Value $Backup.omnistack_cluster_id
        $c | Add-Member -Type NoteProperty -Name OmniStackClusterName -Value $Backup.omnistack_cluster_name
        $omniBackups += $c
    }
    $omniBackups | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Backup") }

    return $omniBackups
}


function Backup-OmniStackVM
{
<#

#>

    [CmdletBinding()]
    param(
	
	[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
    [psobject]$VM,
	
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$Name,
	
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="DestinationCluster")]
    [string]$DestinationCluster,
	
    [Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="BackupName")]
    [string]$BackupName,
	
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="Retention")]
    [string]$Retention,
	
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [Parameter(ParameterSetName="AppConsistent")]
	[string]$AppConsistent
    )

    $DestinationClusterTemp = Get-OmniStackClusters | where {$_.Name -eq $DestinationCluster}
	$DestinationClusterID = $DestinationClusterTemp.Id
	
	if ($vm -eq $null) {
	$vm = Get-OmniStackVM -Name $Name
	}

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $($VM.ID) + "/backup"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("destination_id", "$DestinationClusterID")
    $body.Add("app_consistent", "$AppConsistent")
    $body.Add("backup_name", "$BackupName")
    $body.Add("retention", "$Retention")
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

function Restore-OmniStackVM
{
<#

#>

    [CmdletBinding()]
    param(
	
    [Parameter(Mandatory=$true,ParameterSetName="BackupName")]
    [string]$BackupName,
	
	[Parameter(Mandatory=$false,ParameterSetName="BackupName")]
	[Parameter(ParameterSetName="Name")]
    [string]$Name,
	
	[Parameter(Mandatory=$false,ParameterSetName="BackupName")]
	[Parameter(ParameterSetName="NewVMName")]
    [string]$NewVMName,
	
    [Parameter(Mandatory=$false,ParameterSetName="BackupName")]
	[Parameter(ParameterSetName="DestinationDatastore")]
    [string]$DestinationDatastore,
	
	[Parameter(Mandatory=$false,ParameterSetName="BackupName")]
	[Parameter(ParameterSetName="RestoreOriginal")]
    [bool]$RestoreOriginal
    )

    $BackupTemp = Get-OmniStackBackups | where {$_.Name -eq $BackupName -and $_.VirtualMachineName -eq $Name}
	$BackupID = $BackupTemp.Id
	
	$DatastoreTemp = Get-OmniStackDatastores | where {$_.Name -eq $DestinationDatastore}
	$DatastoreID = $DatastoreTemp.Id
	
	if ($RestoreOriginal -eq $null -or $RestoreOriginal -eq $false) {
    $uri = $($Global:OmniStackConnection.Server) + "/api/backups/" + $($BackupID) + "/restore?restore_original=false"
	}
	
	else{
	$uri = $($Global:OmniStackConnection.Server) + "/api/backups/" + $($BackupID) + "/restore?restore_original=true"
	Write-Host "The original VM from backup $BackupName is being restored. Any new VM name will be ignored."
	}
	
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
	
	if ($RestoreOriginal -eq $false -or $RestoreOriginal -eq $null) {
		if ($NewVMName -eq $null) {
    	$body.Add("virtual_machine_name", "$Name")
		}
		else{
		$body.Add("virtual_machine_name", "$NewVMName")
		}
	}
	
	if ($DatastoreID -ne $null) {
	$body.Add("datastore_id", "$DatastoreID")
	}
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

function Rename-OmniStackBackup
{
<#

#>

    [CmdletBinding()]
    param(
	
    [Parameter(Mandatory=$false,ParameterSetName="BackupName")]
    [string]$BackupName,
	
	[Parameter(Mandatory=$true,ParameterSetName="BackupName")]
	[Parameter(ParameterSetName="Name")]
    [string]$Name
    )

    $BackupTemp = Get-OmniStackBackups | where {$_.Name -eq $BackupName}
	$BackupID = $BackupTemp.Id
	
    $uri = $($Global:OmniStackConnection.Server) + "/api/backups/" + $($BackupID) + "/rename"
	
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("backup_name", "$Name")
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

function Remove-OmniStackBackup
{
<#

#>

    [CmdletBinding()]
    param(
	
    [Parameter(Mandatory=$true,ParameterSetName="BackupName")]
    [string]$BackupName
    )

    $BackupTemp = Get-OmniStackBackups | where {$_.Name -eq $BackupName}
	$BackupID = $BackupTemp.Id
	
    $uri = $($Global:OmniStackConnection.Server) + "/api/backups/" + $($BackupID)
	
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Delete
	
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

<#
-----------------------------------------------------------------------------
OMNISTACK CLUSTER FUNCTIONS
-----------------------------------------------------------------------------
#>

function Get-OmniStackClusters
{
<#

#>

    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$false,ParameterSetName="Name")]
    [string]$Name
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/omnistack_clusters"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("show_optional_fields", "false")
    $body.Add("name", "$Name")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    $omniclusters = @()
    foreach ($cluster in $response.omnistack_clusters)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $cluster.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $cluster.name
        $c | Add-Member -Type NoteProperty -Name Type -Value $cluster.type
		$c | Add-Member -Type NoteProperty -Name HypervisorManagementSystem -Value $cluster.hypervisor_management_system
		$c | Add-Member -Type NoteProperty -Name ArbiterAddress -Value $cluster.arbiter_address
		$c | Add-Member -Type NoteProperty -Name ArbiterConnected -Value $cluster.arbiter_connected
        $c | Add-Member -Type NoteProperty -Name Members -Value $cluster.members
        $c | Add-Member -Type NoteProperty -Name AllocatedCapacity -Value $cluster.allocated_capacity
        $c | Add-Member -Type NoteProperty -Name CompressionRatio -Value $cluster.compression_ratio
        $c | Add-Member -Type NoteProperty -Name DeduplicationRatio -Value $cluster.deduplication_ratio
        $c | Add-Member -Type NoteProperty -Name EfficiencyRatio -Value $cluster.efficiency_ratio
        $c | Add-Member -Type NoteProperty -Name FreeSpace -Value $cluster.free_space
        $c | Add-Member -Type NoteProperty -Name LocalBackupCapacity -Value $cluster.local_backup_capacity
        $c | Add-Member -Type NoteProperty -Name RemoteBackupCapacity -Value $cluster.remote_backup_capacity
        $c | Add-Member -Type NoteProperty -Name StoredCompressedData -Value $cluster.stored_compressed_data
        $c | Add-Member -Type NoteProperty -Name StoredUncompressedData -Value $cluster.stored_uncompressed_data
        $c | Add-Member -Type NoteProperty -Name UsedCapacity -Value $cluster.used_capacity
        $c | Add-Member -Type NoteProperty -Name UsedLogicalCapacity -Value $cluster.used_logical_capacity
        $omniclusters += $c
    }
    $omniclusters | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.OmniStackClusters") }

    return $omniclusters
}

<#
-----------------------------------------------------------------------------
OMNISTACK HOSTS FUNCTIONS
-----------------------------------------------------------------------------
#>

function Get-OmniStackHosts
{
<#

#>

    [CmdletBinding()]
    
	$uri = $($Global:OmniStackConnection.Server) + "/api/hosts?show_optional_fields=true"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $body = @{}
    $body.Add("show_optional_fields", "false")
    $body.Add("name", "$Name")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Get
    $omnihosts= @()
    foreach ($oshost in $response.hosts)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $oshost.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $oshost.name
        $c | Add-Member -Type NoteProperty -Name State -Value $oshost.state
        $c | Add-Member -Type NoteProperty -Name Model -Value $oshost.model
        $c | Add-Member -Type NoteProperty -Name Version -Value $oshost.version
        $c | Add-Member -Type NoteProperty -Name Type -Value $oshost.type
        $c | Add-Member -Type NoteProperty -Name VirtualControllerName -Value $oshost.virtual_controller_name
		$c | Add-Member -Type NoteProperty -Name FederationIp -Value $oshost.federation_ip
		$c | Add-Member -Type NoteProperty -Name ManagementIp -Value $oshost.management_ip
        $c | Add-Member -Type NoteProperty -Name StorageIp -Value $oshost.storage_ip
        $c | Add-Member -Type NoteProperty -Name CurrentFeatureLevel -Value $oshost.current_feature_level
        $c | Add-Member -Type NoteProperty -Name PotentialFeatureLevel -Value $oshost.potential_feature_level
        $c | Add-Member -Type NoteProperty -Name UpgradeState -Value $oshost.upgrade_state
        $c | Add-Member -Type NoteProperty -Name CanRollback -Value $oshost.can_rollback
        $c | Add-Member -Type NoteProperty -Name PolicyEnabled -Value $oshost.policy_enabled
        $c | Add-Member -Type NoteProperty -Name HypervisorManagementSystem -Value $oshost.hypervisor_management_system
        $c | Add-Member -Type NoteProperty -Name HypervisorObjectId -Value $oshost.hypervisor_object_id
		$c | Add-Member -Type NoteProperty -Name ComputeClusterHypervisorObjectId -Value $oshost.compute_cluster_hypervisor_object_id
		$c | Add-Member -Type NoteProperty -Name ComputeClusterName -Value $oshost.compute_cluster_name
		$c | Add-Member -Type NoteProperty -Name ComputeClusterParentHypervisorObjectId -Value $oshost.compute_cluster_parent_hypervisor_object_id
		$c | Add-Member -Type NoteProperty -Name ComputeClusterParentName -Value $oshost.compute_cluster_parent_name
        $c | Add-Member -Type NoteProperty -Name LocalBackupCapacity -Value $oshost.local_backup_capacity
        $c | Add-Member -Type NoteProperty -Name RemoteBackupCapacity -Value $oshost.remote_backup_capacity
        $c | Add-Member -Type NoteProperty -Name StoredCompressedData -Value $oshost.stored_compressed_data
        $c | Add-Member -Type NoteProperty -Name StoredUncompressedData -Value $oshost.stored_uncompressed_data
        $c | Add-Member -Type NoteProperty -Name StoredVirtualMachineData -Value $oshost.stored_virtual_machine_data
		$c | Add-Member -Type NoteProperty -Name UsedCapacity -Value $oshost.used_capacity
        $c | Add-Member -Type NoteProperty -Name UsedLogicalCapacity -Value $oshost.used_logical_capacity
        $c | Add-Member -Type NoteProperty -Name FreeSpace -Value $oshost.free_space
        $c | Add-Member -Type NoteProperty -Name CapacitySavings -Value $oshost.capacity_savings
        $c | Add-Member -Type NoteProperty -Name AllocatedCapacity -Value $oshost.allocated_capacity
        $c | Add-Member -Type NoteProperty -Name CompressionRatio -Value $oshost.compression_ratio
        $c | Add-Member -Type NoteProperty -Name DeduplicationRatio -Value $oshost.deduplication_ratio
        $c | Add-Member -Type NoteProperty -Name EfficiencyRatio -Value $oshost.efficiency_ratio


        $omnihosts += $c
    }
    $omnihosts | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.OmniStackHosts") }

    return $omnihosts
}

function Get-OmniStackHost
{
<#

#>

    [CmdletBinding()]

    param(
    [Parameter(Mandatory=$true,ParameterSetName="Name")]
    [string]$Name
    )

	$OSHostTemp = Get-OmniStackHosts | where {$_.Name -eq $Name}
	$OSHostId = $OSHostTemp.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/hosts/" + $($OSHostId)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
	$omnihost = @()
	
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name ID -Value $response.host.id
        $c | Add-Member -Type NoteProperty -Name Name -Value $response.host.name
        $c | Add-Member -Type NoteProperty -Name State -Value $response.host.state
        $c | Add-Member -Type NoteProperty -Name Model -Value $response.host.model
        $c | Add-Member -Type NoteProperty -Name Version -Value $response.host.version
        $c | Add-Member -Type NoteProperty -Name Type -Value $response.host.type
        $c | Add-Member -Type NoteProperty -Name VirtualControllerName -Value $response.host.virtual_controller_name
		$c | Add-Member -Type NoteProperty -Name FederationIp -Value $response.host.federation_ip
		$c | Add-Member -Type NoteProperty -Name ManagementIp -Value $response.host.management_ip
        $c | Add-Member -Type NoteProperty -Name StorageIp -Value $response.host.storage_ip
        $c | Add-Member -Type NoteProperty -Name CurrentFeatureLevel -Value $response.host.current_feature_level
        $c | Add-Member -Type NoteProperty -Name PotentialFeatureLevel -Value $response.host.potential_feature_level
        $c | Add-Member -Type NoteProperty -Name UpgradeState -Value $response.host.upgrade_state
        $c | Add-Member -Type NoteProperty -Name CanRollback -Value $response.host.can_rollback
        $c | Add-Member -Type NoteProperty -Name PolicyEnabled -Value $response.host.policy_enabled
        $c | Add-Member -Type NoteProperty -Name HypervisorManagementSystem -Value $response.host.hypervisor_management_system
        $c | Add-Member -Type NoteProperty -Name HypervisorObjectId -Value $response.host.hypervisor_object_id
		$c | Add-Member -Type NoteProperty -Name ComputeClusterHypervisorObjectId -Value $response.host.compute_cluster_hypervisor_object_id
		$c | Add-Member -Type NoteProperty -Name ComputeClusterName -Value $response.host.compute_cluster_name
		$c | Add-Member -Type NoteProperty -Name ComputeClusterParentHypervisorObjectId -Value $response.host.compute_cluster_parent_hypervisor_object_id
		$c | Add-Member -Type NoteProperty -Name ComputeClusterParentName -Value $response.host.compute_cluster_parent_name
        $c | Add-Member -Type NoteProperty -Name LocalBackupCapacity -Value $response.host.local_backup_capacity
        $c | Add-Member -Type NoteProperty -Name RemoteBackupCapacity -Value $response.host.remote_backup_capacity
        $c | Add-Member -Type NoteProperty -Name StoredCompressedData -Value $response.host.stored_compressed_data
        $c | Add-Member -Type NoteProperty -Name StoredUncompressedData -Value $response.host.stored_uncompressed_data
        $c | Add-Member -Type NoteProperty -Name StoredVirtualMachineData -Value $response.host.stored_virtual_machine_data
		$c | Add-Member -Type NoteProperty -Name UsedCapacity -Value $response.host.used_capacity
        $c | Add-Member -Type NoteProperty -Name UsedLogicalCapacity -Value $response.host.used_logical_capacity
        $c | Add-Member -Type NoteProperty -Name FreeSpace -Value $response.host.free_space
        $c | Add-Member -Type NoteProperty -Name CapacitySavings -Value $response.host.capacity_savings
        $c | Add-Member -Type NoteProperty -Name AllocatedCapacity -Value $response.host.allocated_capacity
        $c | Add-Member -Type NoteProperty -Name CompressionRatio -Value $response.host.compression_ratio
        $c | Add-Member -Type NoteProperty -Name DeduplicationRatio -Value $response.host.deduplication_ratio
        $c | Add-Member -Type NoteProperty -Name EfficiencyRatio -Value $response.host.efficiency_ratio
		
        $omnihost += $c
    $omnihost | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.OmniStackHost") }
	
    return $omnihost
}

function Get-OmniStackHostHardware
{
<#

#>

    [CmdletBinding()]

    param(
    [Parameter(ParameterSetName="Name")]
    [string]$HostName,
	[Parameter(ValueFromPipeline=$true)]
	[psobject]$HostObj
    )
	
	if ($HostName -ne $null -and $HostName -ne "") {
		$HostObj = Get-OmniStackHost -Name $HostName
	}
	
	$OSHostId = $HostObj.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/hosts/" + $($OSHostId) + "/hardware"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
	$omnihost = @()
	
        $c = New-Object System.Object
			$c | Add-Member -Type NoteProperty -Name ID -Value $response.host.host_id
        	$c | Add-Member -Type NoteProperty -Name Name -Value $response.host.name
        	$c | Add-Member -Type NoteProperty -Name Status -Value $response.host.status
        	$c | Add-Member -Type NoteProperty -Name Manufacturer -Value $response.host.manufacturer
        	$c | Add-Member -Type NoteProperty -Name Model -Value $response.host.model_number
        	$c | Add-Member -Type NoteProperty -Name SerialNumber -Value $response.host.serial_number
			$c | Add-Member -Type NoteProperty -Name Battery -Value $response.host.battery
			$c | Add-Member -Type NoteProperty -Name AcceleratorCard -Value $response.host.accelerator_card
			$c | Add-Member -Type NoteProperty -Name LogicalDrives -Value $response.host.logical_drives
	
        $omnihost += $c
    	$omnihost | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.OmniStackHost.Hardware") }   
		
	return $omnihost
	
}


<#
-----------------------------------------------------------------------------
POLICY FUNCTIONS
-----------------------------------------------------------------------------
#>


function New-OmniStackBackupPolicy
{
<#

#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true,ParameterSetName="PolicyName")]
    [string]$PolicyName
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/policies"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $body = @{}
    $body.Add("name", $PolicyName)
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

function Get-OmniStackBackupPolicies
{
<#

#>

    [CmdletBinding()]

    $uri = $($Global:OmniStackConnection.Server) + "/api/policies"
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
    $omnipolicy = @()
    foreach ($policy in $response.policies)
    {
        $c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name Name -Value $policy.name
        $c | Add-Member -Type NoteProperty -Name ID -Value $policy.id
        $c | Add-Member -Type NoteProperty -Name Rules -Value $policy.rules
        $omnipolicy += $c
    }
    
    $omnipolicy | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Policies") }

    return $omnipolicy
}

function Get-OmniStackBackupPolicy
{
<#

#>

    [CmdletBinding()]
	param(
	[Parameter(Mandatory=$true)]
    [String]$PolicyName
	)
	
	$PolicyTemp = Get-OmniStackBackupPolicies | where {$_.Name -eq $PolicyName}
	$PolicyID = $PolicyTemp.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/policies/" + $($PolicyID)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Get
	
    $omnipolicy = @()

		$c = New-Object System.Object
        $c | Add-Member -Type NoteProperty -Name Name -Value $response.policy.name
        $c | Add-Member -Type NoteProperty -Name ID -Value $response.policy.id
        $c | Add-Member -Type NoteProperty -Name Rules -Value $response.policy.rules
        $omnipolicy += $c
    
    $omnipolicy | % { $_.PSObject.TypeNames.Insert(0,"Simplivity.Policy") }

    return $omnipolicy
}

function Remove-OmniStackBackupPolicy
{
<#

#>

    [CmdletBinding()]
	param(
	[Parameter(Mandatory=$false,ParameterSetName="PolicyName")]
    [String]$PolicyName,
	[Parameter(Mandatory=$false,ValueFromPipeline=$true,ParameterSetName="PolicyName")]
	[psobject]$Policy
	)
	
	if ($PolicyName -ne $null -and $PolicyName -ne "") {
		$Policy = Get-OmniStackBackupPolicy -PolicyName $PolicyName
	}
	
	$PolicyID = $Policy.Id
	
	$uri = $($Global:OmniStackConnection.Server) + "/api/policies/" + $($PolicyID)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Delete

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

function New-OmniStackBackupPolicyRule
{
<#

#>

    [CmdletBinding()]
	param(
	[Parameter(Mandatory=$false,ValueFromPipeline=$true,ParameterSetName="Name")]
	[psobject]$Policy,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="PolicyName")]
    [String]$PolicyName,
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="ReplaceAllRules")]
    [Bool]$ReplaceAllRules,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="AppConsistent")]
    [Bool]$AppConsistent,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="ConsistencyType")]
    [String]$ConsistencyType,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="Days")]
    [String]$Days,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="DestinationCluster")]
    [String]$DestinationCluster,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="StartTime")]
    [String]$StartTime,
	[Parameter(Mandatory=$false,ParameterSetName="Name")]
	[Parameter(ParameterSetName="EndTime")]
    [String]$EndTime,
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="Frequency")]
    [Int32]$Frequency,
	[Parameter(Mandatory=$true,ParameterSetName="Name")]
	[Parameter(ParameterSetName="Retention")]
    [Int32]$Retention
	)
	
	if ($PolicyName -ne $null -and $PolicyName -ne "") {
		$Policy = Get-OmniStackBackupPolicy -PolicyName $PolicyName
	}
	
	$PolicyID = $Policy.Id
	
	$ClusterTemp = Get-OmniStackClusters | where {$_.Name -eq $ClusterName}
	$ClusterID = $ClusterTemp.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/policies/" + $($PolicyID) + "/rules?replace_all_rules=" + $($ReplaceAllRules)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
	$body = @{}
    if ($AppConsistent -ne $false) {$body.Add("application_consistent", $AppConsistent)}
	if ($ConsistencyType -ne "") {$body.Add("consistency_type", $ConsistencyType)}
	if ($Days -ne "") {$body.Add("days", $Days)}
	if ($ClusterID -ne $null) {$body.Add("destination_id", $ClusterID)}
	if ($EndTime -ne 0 -and $EndTime -ne "") {$body.Add("end_time", $EndTime)}
	$body.Add("frequency", $Frequency)
	$body.Add("retention", $Retention)
	if ($StartTime -ne 0 -and $StartTime -ne "") {$body.Add("start_time", $StartTime)}
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

function Remove-OmniStackBackupPolicyRule
{
<#

#>

    [CmdletBinding()]
	param(
	[Parameter(Mandatory=$false,ParameterSetName="PolicyName")]
    [String]$PolicyName,
	[Parameter(Mandatory=$false,ValueFromPipeline=$true,ParameterSetName="PolicyName")]
	[psobject]$Policy,
	[Parameter(Mandatory=$true,ParameterSetName="PolicyName")]
	[Parameter(ParameterSetName="ReplaceAllRules")]
    [Int32]$RuleID
	)
	
	if ($PolicyName -ne $null -and $PolicyName -ne "") {
		$Policy = Get-OmniStackBackupPolicy -PolicyName $PolicyName
	}
	
	$PolicyID = $Policy.Id

    $uri = $($Global:OmniStackConnection.Server) + "/api/policies/" + $($PolicyID) + "/rules/" + $($RuleID)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1+json")
    $response = Invoke-RestMethod -Uri $uri -Headers $header -Method Delete
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
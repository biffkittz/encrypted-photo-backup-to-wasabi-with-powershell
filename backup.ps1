
<#

.SYNOPSIS
    Encrypt and upload photos (or other files) to Wasabi S3-compatible storage in parallel using runspaces.

.DESCRIPTION
    Encrypt and upload photos to Wasabi S3-compatible storage in parallel using runspaces.
    Use SQLite to track uploaded files by their SHA256 hash to avoid duplicate uploads.
    Encrypts files using AES-256 encryption with a password before uploading.
    TODO: Download and decrypt functionality.
    TODO: Compression before encryption.
    TODO: Better error handling and retries for uploads.

.PARAMETER WasabiAccessKeyId
    Access key ID for Wasabi S3-compatible storage
.PARAMETER WasabiSecretAccessKey
    Secret access key for Wasabi S3-compatible storage
.PARAMETER EncryptionPassword
    Password used for AES-256 encryption/decryption of files
.PARAMETER BucketName
    Name of the Wasabi S3 bucket to upload files to
.PARAMETER EndpointUrl
    Endpoint URL for the Wasabi S3-compatible storage (default: https://s3.us-east-2.wasabisys.com)
.PARAMETER PhotoDirectory
    Directory containing photos to back up (default: ./photos)
.PARAMETER DatabasePath
    Path to the SQLite database file for tracking uploaded files (default: ./photo.db)
.PARAMETER RunspacesMaxCount
    Maximum number of parallel runspaces for uploading files (default: 5)

.EXAMPLE
    .\backup.ps1 `
        -WasabiAccessKeyId <key_id> `
        -WasabiSecretAccessKey <secret_access_key> `
        -EncryptionPassword <enc_password> `
        -BucketName <bucket_name> `
        -EndpointUrl "https://s3.us-east-1.wasabisys.com" `
        -PhotoDirectory "./photos" `
        -DatabasePath "./photo.db" `
        -RunspacesMaxCount 8

.NOTES
Requires:
- AWS Tools for PowerShell (AWSPowerShell.NetCore module)
- AWS CLI installed and configured
- PSSQLite module for SQLite database access
- SQLite
- Wasabi account

#>

param (
    [Parameter(Mandatory = $true)]
    [string] $WasabiAccessKeyId,
    [Parameter(Mandatory = $true)]
    [string] $WasabiSecretAccessKey,
    [Parameter(Mandatory = $true)]
    [string] $EncryptionPassword,
    [Parameter(Mandatory = $true)]
    [string] $BucketName,
    [string] $EndpointUrl = "https://s3.us-east-2.wasabisys.com",
    [string] $PhotoDirectory = "./photos",
    [string] $DatabasePath = "./photo.db",
    [int]    $RunspacesMaxCount = 5
)

#region Initial Setup
Import-Module -Name AWSPowerShell.NetCore
Import-Module -Name PSSQLite

function Write-Message {
    param (
        [ValidateSet("Info", "Warning", "Error", "Important")]
        [string]$MessageType = "Info",
        [string]$Message
    )

    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")

    if ($MessageType -eq "Error") {
        Write-Host "[$TimeStamp] [$MessageType] $Message" -ForegroundColor Red
        return
    }

    if ($MessageType -eq "Warning") {
        Write-Host "[$TimeStamp] [$MessageType] $Message" -ForegroundColor Yellow
        return
    }

    if ($MessageType -eq "Info") {
        Write-Host "[$TimeStamp] [$MessageType] $Message" -ForegroundColor Green
        return
    }

    if ($MessageType -eq "Important") {
        Write-Host "[$TimeStamp] [$MessageType] $Message" -ForegroundColor Cyan
        return
    }
}

# Initialize runspace pool for parallel I/O
$global:RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(
    1,
    $RunspacesMaxCount
)

$global:RunspacePool.Open()

# Set Wasabi credentials using AWS PowerShell module
Set-AWSCredentials -AccessKey $WasabiAccessKeyId -SecretKey $WasabiSecretAccessKey

# Ensure the bucket exists, create if it does not
$bucketExists = Test-S3Bucket -BucketName $BucketName -EndpointUrl $EndpointUrl

if (!$bucketExists) {
    Write-Message -MessageType Warning -Message "Bucket $BucketName does not exist. Creating..."
    New-S3Bucket -BucketName $BucketName -EndpointUrl $EndpointUrl
} else {
    Write-Message -MessageType Info -Message "Bucket $BucketName already exists."
}

# Ensure the SQLite database and Photo table exist
Invoke-SqliteQuery -DataSource $DatabasePath -Query @'
CREATE TABLE IF NOT EXISTS Photo (
    hash TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    t TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
'@
#endregion

#region Runspace-related functions
function Wait-ForRunspacesCompletionAndThrowOnTimeout {
    param (
        [array]  $Runspaces,
        [int]    $TimeoutSeconds,
        [string] $ErrorMessage = "Timeout waiting for runspaces to complete"
    )

    $StartTime = Get-Date
    $millisecondElapsedCount = 10

    Write-Message `
        -MessageType "Info" `
        -Message "Waiting for runspaces to complete with timeout of $TimeoutSeconds seconds"

    while ($Runspaces.State.IsCompleted -contains $False) {
        if ( (Get-Date) - $StartTime -gt (New-TimeSpan -Seconds $TimeoutSeconds) ) {
            Write-Message -MessageType "Error" -Message "Timeout waiting for runspaces to complete"
            throw $ErrorMessage ?? "Timeout waiting for runspaces to complete"
        }

        # Output progress, if any, every second
        if ($millisecondElapsedCount % 200 -eq 0) {
            foreach ($runspace in $Runspaces) {
                if ($runspace.ProgressHash -and $runspace.ProgressHash['ProgressReport']) {
                    Write-Message -MessageType Info -Message $($runspace.ProgressHash['ProgressReport'])
                }
            }
        }

        Start-Sleep -Milliseconds 10
        $millisecondElapsedCount += 10
    }
}

function Get-RunspacesResultsAndDispose {
    param (
        [array] $Runspaces
    )

    Write-Message `
        -MessageType "Info" `
        -Message "Collecting runspaces results and disposing runspaces..."

    $runspaceResults = @()
    $Runspaces | ForEach-Object {
        $runspaceResults += "$($_.Runspace.EndInvoke($_.State))`n"
        $_.Runspace.Dispose() # Dispose runspace to free resources after gathering results
    }

    Write-Message -MessageType Important -Message "`n$runspaceResults"
}

function Invoke-UploadFileToWasabiScriptBlockInRunspace {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [Parameter(Mandatory = $true)]
        [string] $BucketName,
        [Parameter(Mandatory = $true)]
        [string] $KeyName,
        [Parameter(Mandatory = $true)]
        [string] $FileHash,
        [Parameter(Mandatory = $true)]
        [string] $EndpointUrl,
        [Parameter(Mandatory = $true)]
        [string] $DatabasePath
    )

    $UploadFileToWasabiScriptBlock = {
        param(
            $progressHash,
            $FilePath,
            $BucketName,
            $KeyName,
            $FileHash,
            $EndpointUrl,
            $DatabasePath = "./photo.db"
        )

        try  {
            # attempt upload only if hash does not already exist in database
            if ($(Invoke-SqliteQuery -DataSource $DatabasePath -Query "SELECT COUNT(*) AS COUNT FROM Photo WHERE Hash == '$FileHash'").'COUNT' -eq 0) {
                $progressHash['ProgressReport'] = "Uploading $FilePath to Wasabi bucket $BucketName as $KeyName..."

                $safeDate = (Get-Date).ToString("yyyy-MM-dd")
                aws s3 cp $FilePath "s3://$BucketName/$safeDate/$keyName" --endpoint-url $EndpointUrl --checksum-algorithm=CRC32

                #if ($LASTEXITCODE -ne 0) {
                #    throw "Error uploading file $FilePath to Wasabi"
                #}

                # insert hash and filename into database if upload was successful
                Invoke-SqliteQuery -DataSource $DatabasePath -Query "INSERT INTO Photo (hash, name, location) VALUES ('$FileHash', '$KeyName', '$BucketName/$safeDate/');"
                $progressHash['ProgressReport'] = "Uploaded $FilePath to Wasabi bucket $BucketName as $KeyName"
                Write-Output "Uploaded $KeyName to Wasabi bucket $BucketName"
            } else {
                $progressHash['ProgressReport'] = "File with hash $FileHash already exists in database. Skipping upload of $FilePath."
                Write-Output "File with hash beginning with $($FileHash.Substring(0,10)) already exists in database. Skipping upload of $KeyName."
            }
        } catch {
            $progressHash['ProgressReport'] = "Error uploading $FilePath to Wasabi: $_"
            Write-Output "Error uploading $KeyName to Wasabi: $_"
        }
    }

    # Synchronized hashtable to report progress from runspace
    $progressHash = [hashtable]::Synchronized(@{})

    $Runspace = [powershell]::Create().AddScript($UploadFileToWasabiScriptBlock)

    $null = $Runspace.AddArgument($progressHash)
    $null = $Runspace.AddArgument($FilePath)
    $null = $Runspace.AddArgument($BucketName)
    $null = $Runspace.AddArgument($KeyName)
    $null = $Runspace.AddArgument($FileHash)
    $null = $Runspace.AddArgument($EndpointUrl)
    $null = $Runspace.AddArgument($DatabasePath)

    # Use the global runspace pool
    $Runspace.RunspacePool = $global:RunspacePool

    # Start the runspace asynchronously
    return @(New-Object PSObject -Property @{
        Runspace = $Runspace
        State = $Runspace.BeginInvoke()
        ProgressHash = $progressHash
    })
}
#endregion

#region Encryption/Decryption Functions
function Protect-File {
    param (
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    if (-not (Test-Path -Path $FilePath)) {
        Write-Error "File $FilePath does not exist." -BackgroundColor Red
        return
    }

    $file = Get-Item -Path $FilePath
    $isEncrypted = $file.Extension -eq ".encrypted"

    try {
        if ($isEncrypted) {
            Write-Message -MessageType Info -Message "Decrypting file $FilePath..."
            $outputPath = $FilePath -replace "\.encrypted$", ""
            Decrypt-FileBytes -InputPath $FilePath -OutputPath $outputPath -Password $Password
            Write-Message -MessageType Info -Message "File decrypted to $outputPath"
        } else {
            Write-Message -MessageType Info -Message "Encrypting file $FilePath..."
            $outputPath = "$FilePath.encrypted"
            Encrypt-FileBytes -InputPath $FilePath -OutputPath $outputPath -Password $Password
            Write-Message -MessageType Info -Message "File encrypted to $outputPath"
        }
    } catch {
        Write-Error "An error occurred during encryption/decryption: $_"
    }
}

function Encrypt-FileBytes {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InputPath,
        [Parameter(Mandatory = $true)]
        [string] $OutputPath,
        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $fileBytes = [System.IO.File]::ReadAllBytes($InputPath)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC

    $salt = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($salt)

    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
    $aes.Key = $pbkdf2.GetBytes($aes.KeySize / 8) # 32 in our case
    $aes.GenerateIV()

    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)

    $outputStream = [System.IO.File]::OpenWrite($OutputPath)
    $outputStream.Write($salt, 0, $salt.Length)
    $outputStream.Write($aes.IV, 0, $aes.IV.Length)
    $outputStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
    $outputStream.Close()
    
    $aes.Dispose()
    $pbkdf2.Dispose()
}

function Decrypt-FileBytes {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InputPath,
        [Parameter(Mandatory = $true)]
        [string] $OutputPath,
        [Parameter(Mandatory = $true)]
        [string] $Password
    )

    $encryptedData = [System.IO.File]::ReadAllBytes($InputPath)

    $salt = $encryptedData[0..31]
    $iv = $encryptedData[32..47]
    $encryptedBytes = $encryptedData[48..($encryptedData.Length - 1)]

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.IV = $iv

    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
    $aes.Key = $pbkdf2.GetBytes($aes.KeySize / 8) # 32 in our case

    $decryptor = $aes.CreateDecryptor()
    try {
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        [System.IO.File]::WriteAllBytes($OutputPath, $decryptedBytes)
    } catch {
        throw "Decryption failed. Possibly due to incorrect password or corrupted file."
    } finally {
        $aes.Dispose()
        $pbkdf2.Dispose()
    }
}
#endregion

# Entry point for photo backup
function Start-PhotoBackup {
    param (
        [string] $PhotoDirectory
    )

    if (!(Test-Path -Path "./outbox")) {
        Write-Message -MessageType Info "Photo outbox directory does not exist. Creating..."
        New-Item -ItemType Directory -Path "$PhotoDirectory/outbox"
    }

    # Encrypt photos in the photo directory and move them to the outbox directory
    Get-ChildItem -Path $PhotoDirectory | ForEach-Object {
        $file = $_

        # compute hash of the unencrypted file (the same file after different encryptions will have different hashes)
        $hashString = $(Get-FileHash -Path $file -Algorithm SHA512).Hash

        if ($file.Extension -eq ".encrypted") {
            Write-Message -MessageType Warning -Message "Deleting stale encrypted file $file..."
            Remove-Item -Path $file.FullName
            return
        }

        if ($file.Extension -in (".jpeg", ".png", ".jpg")) {
            #gzip -9k $file
            Protect-File -FilePath $file.FullName -Password $EncryptionPassword

            # Move encrypted file to outbox directory
            Move-Item -Path "$PhotoDirectory/$($file.Name).encrypted" -Destination "./outbox/$($file.Name.Replace('-', '_'))-$hashString.encrypted"

            Write-Message -MessageType Info -Message "Encrypted photo $file"
        }
    }
    
    # if the outbox directory contains encrypted files, upload them to Wasabi in parallel
    if ($(Get-ChildItem -Path "./outbox" | Where-Object { $_.Extension -eq ".encrypted" }).Count -gt 0)
    {
        Write-Message -MessageType Info -Message "Beginning upload of encrypted files to Wasabi..."
        $runspaces = @()
        Get-ChildItem -Path "./outbox" | Where-Object { $_.Extension -eq ".encrypted" } | ForEach-Object {
            $file = $_
            $keyName = "$($file.Name.Split("-")[0]).encrypted"
            $fileHash = $file.Name.Split("-")[1] -replace "\.encrypted$", "" # hash part of the filename

            Write-Message -MessageType Info -Message "Uploading $keyName to Wasabi if necessary..."

            $runspaces += Invoke-UploadFileToWasabiScriptBlockInRunspace `
                -FilePath $file.FullName `
                -BucketName $BucketName `
                -KeyName $keyName `
                -FileHash $fileHash `
                -EndpointUrl $EndpointUrl `
                -DatabasePath $DatabasePath
        }

        Wait-ForRunspacesCompletionAndThrowOnTimeout -Runspaces $runspaces -TimeoutSeconds 300

        # Output runspace results
        Get-RunspacesResultsAndDispose -Runspaces $runspaces
    }

    # delete encrypted files from outbox after upload
    Get-ChildItem -Path "./outbox" | Where-Object { $_.Extension -eq ".encrypted" } | ForEach-Object {
        $file = $_
        Write-Message -MessageType Info -Message "Deleting processed file $($file.Name.Substring(0, 80))..."
        Remove-Item -Path $file.FullName
    }
}

Start-PhotoBackup -PhotoDirectory $PhotoDirectory

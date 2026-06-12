[CmdletBinding()]
param(
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$UpgradeCode = '{C49D6E5F-57E0-4D2C-A479-28F7C792E2E9}'
$ComponentCode = '{A0D593C1-6763-439D-94F1-234F36A0C352}'

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function Get-WorkspaceVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CargoToml
    )

    $content = Get-Content -Raw -LiteralPath $CargoToml
    $match = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
    if (!$match.Success) {
        throw "workspace version was not found in $CargoToml"
    }
    return $match.Groups[1].Value
}

function Require-FileContains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $content = Get-Content -Raw -LiteralPath $Path
    if (!$content.Contains($Text)) {
        throw "required MSI extracted file content is missing from $Path`: $Text"
    }
}

function Require-ManifestSmokeCase {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!($Manifest.manual_smoke -contains $Name)) {
        throw "MSI extracted manifest manual_smoke is missing: $Name"
    }
}

function Escape-MsiSql {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return 'NULL'
    }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Invoke-MsiSql {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Sql
    )

    try {
        $view = $Database.OpenView($Sql)
    } catch {
        throw "MSI SQL open failed: $Sql`n$($_.Exception.Message)"
    }
    try {
        $view.Execute()
    } catch {
        throw "MSI SQL execute failed: $Sql`n$($_.Exception.Message)"
    } finally {
        $view.Close()
    }
}

function Insert-MsiRow {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Table,

        [Parameter(Mandatory = $true)]
        [string[]]$Columns,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]]$Values
    )

    $escapedColumns = ($Columns | ForEach-Object { "``$_``" }) -join ', '
    $escapedValues = ($Values | ForEach-Object {
        if ($null -eq $_) { 'NULL' } elseif ($_ -is [int]) { $_.ToString() } else { Escape-MsiSql ([string]$_) }
    }) -join ', '
    Invoke-MsiSql -Database $Database -Sql "INSERT INTO ``$Table`` ($escapedColumns) VALUES ($escapedValues)"
}

function Add-MsiStream {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Installer,

        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $record = $Installer.CreateRecord(2)
    $record.StringData(1) = $Name
    $record.SetStream(2, $Path)
    $view = $Database.OpenView('INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)')
    try {
        $view.Execute($record)
    } finally {
        $view.Close()
    }
}

function Get-MsiScalar {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Sql
    )

    try {
        $view = $Database.OpenView($Sql)
    } catch {
        throw "MSI SQL scalar open failed: $Sql`n$($_.Exception.Message)"
    }
    try {
        $view.Execute()
        $record = $view.Fetch()
        if ($null -eq $record) {
            return $null
        }
        return $record.StringData(1).Trim()
    } catch {
        throw "MSI SQL scalar execute failed: $Sql`n$($_.Exception.Message)"
    } finally {
        $view.Close()
    }
}

function Get-MsiCount {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Sql
    )

    try {
        $view = $Database.OpenView($Sql)
    } catch {
        throw "MSI SQL count open failed: $Sql`n$($_.Exception.Message)"
    }
    try {
        $view.Execute()
        $count = 0
        while ($null -ne $view.Fetch()) {
            $count++
        }
        return $count
    } catch {
        throw "MSI SQL count execute failed: $Sql`n$($_.Exception.Message)"
    } finally {
        $view.Close()
    }
}

function Set-MsiSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$PackageCode
    )

    $summary = $Database.SummaryInformation(20)
    $summary.Property(2) = 'Keli Desktop MVP Installer'
    $summary.Property(3) = 'Keli Desktop MVP'
    $summary.Property(4) = 'Keli'
    $summary.Property(7) = 'x64;1033'
    $summary.Property(9) = $PackageCode
    $summary.Property(14) = 200
    $summary.Property(15) = 2
    $summary.Persist()
}

function New-MsiTables {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database
    )

    Invoke-MsiSql $Database 'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR LOCALIZABLE PRIMARY KEY `Property`)'
    Invoke-MsiSql $Database 'CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) LOCALIZABLE PRIMARY KEY `Directory`)'
    Invoke-MsiSql $Database 'CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)'
    Invoke-MsiSql $Database 'CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)'
    Invoke-MsiSql $Database 'CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)'
    Invoke-MsiSql $Database 'CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` SHORT NOT NULL PRIMARY KEY `File`)'
    Invoke-MsiSql $Database 'CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64), `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)'
    Invoke-MsiSql $Database 'CREATE TABLE `Shortcut` (`Shortcut` CHAR(72) NOT NULL, `Directory_` CHAR(72) NOT NULL, `Name` CHAR(128) NOT NULL LOCALIZABLE, `Component_` CHAR(72) NOT NULL, `Target` CHAR(72) NOT NULL, `Arguments` CHAR(255), `Description` CHAR(255) LOCALIZABLE, `Hotkey` SHORT, `Icon_` CHAR(72), `IconIndex` SHORT, `ShowCmd` SHORT, `WkDir` CHAR(72) PRIMARY KEY `Shortcut`)'
    Invoke-MsiSql $Database 'CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)'
    Invoke-MsiSql $Database 'CREATE TABLE `AdminExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)'
}

function Add-StandardSequences {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database
    )

    $installActions = @(
        @('CostInitialize', $null, 800),
        @('FileCost', $null, 900),
        @('CostFinalize', $null, 1000),
        @('InstallValidate', $null, 1400),
        @('InstallInitialize', $null, 1500),
        @('ProcessComponents', $null, 1600),
        @('RemoveShortcuts', $null, 3200),
        @('RemoveFiles', $null, 3500),
        @('InstallFiles', $null, 4000),
        @('CreateShortcuts', $null, 4500),
        @('RegisterUser', $null, 6000),
        @('RegisterProduct', $null, 6100),
        @('PublishFeatures', $null, 6300),
        @('PublishProduct', $null, 6400),
        @('InstallFinalize', $null, 6600)
    )
    foreach ($action in $installActions) {
        Insert-MsiRow $Database 'InstallExecuteSequence' @('Action', 'Condition', 'Sequence') $action
    }

    $adminActions = @(
        @('CostInitialize', $null, 800),
        @('FileCost', $null, 900),
        @('CostFinalize', $null, 1000),
        @('InstallValidate', $null, 1400),
        @('InstallInitialize', $null, 1500),
        @('InstallFiles', $null, 4000),
        @('InstallFinalize', $null, 6600)
    )
    foreach ($action in $adminActions) {
        Insert-MsiRow $Database 'AdminExecuteSequence' @('Action', 'Condition', 'Sequence') $action
    }
}

function New-DesktopCabinet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StageDir,

        [Parameter(Mandatory = $true)]
        [string]$WorkDir
    )

    $ddfPath = Join-Path $WorkDir 'keli-desktop.ddf'
    $cabPath = Join-Path $WorkDir 'keli-desktop.cab'
    @(
        '.Set CabinetNameTemplate=keli-desktop.cab',
        '.Set DiskDirectoryTemplate=.',
        '.Set CompressionType=MSZIP',
        '.Set Cabinet=on',
        '.Set Compress=on',
        '.Set MaxDiskSize=0',
        ('"' + (Join-Path $StageDir 'keli-desktop-shell.exe') + '" KeliDesktopShellExe'),
        ('"' + (Join-Path $StageDir 'README.txt') + '" KeliDesktopReadme'),
        ('"' + (Join-Path $StageDir 'keli-desktop-manifest.json') + '" KeliDesktopManifest')
    ) | Set-Content -LiteralPath $ddfPath -Encoding ASCII

    Push-Location $WorkDir
    try {
        & makecab.exe /F $ddfPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "makecab failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    if (!(Test-Path -LiteralPath $cabPath -PathType Leaf)) {
        throw "cabinet was not produced: $cabPath"
    }
    return $cabPath
}

function Write-DesktopMsi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StageDir,

        [Parameter(Mandatory = $true)]
        [string]$MsiPath,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $required = @(
        (Join-Path $StageDir 'keli-desktop-shell.exe'),
        (Join-Path $StageDir 'README.txt'),
        (Join-Path $StageDir 'keli-desktop-manifest.json')
    )
    foreach ($path in $required) {
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required MSI input is missing: $path"
        }
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $MsiPath) | Out-Null
    if (Test-Path -LiteralPath $MsiPath) {
        Remove-Item -LiteralPath $MsiPath -Force
    }

    $workDir = Join-Path (Split-Path -Parent $MsiPath) 'msi-work'
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($MsiPath, 3)
    $productCode = '{' + ([guid]::NewGuid().ToString().ToUpperInvariant()) + '}'
    $packageCode = '{' + ([guid]::NewGuid().ToString().ToUpperInvariant()) + '}'
    $cabPath = New-DesktopCabinet -StageDir $StageDir -WorkDir $workDir

    Set-MsiSummary -Database $database -PackageCode $packageCode
    New-MsiTables -Database $database

    Insert-MsiRow $database 'Property' @('Property', 'Value') @('ProductCode', $productCode)
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('ProductLanguage', '1033')
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('ProductName', 'Keli Desktop MVP')
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('ProductVersion', $Version)
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('Manufacturer', 'Keli')
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('UpgradeCode', $UpgradeCode)
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('ALLUSERS', '1')
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('INSTALLLEVEL', '1')
    Insert-MsiRow $database 'Property' @('Property', 'Value') @('NativeCoreDefault', 'true')

    Insert-MsiRow $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') @('TARGETDIR', $null, 'SourceDir')
    Insert-MsiRow $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') @('ProgramFiles64Folder', 'TARGETDIR', '.')
    Insert-MsiRow $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') @('INSTALLFOLDER', 'ProgramFiles64Folder', 'Keli')
    Insert-MsiRow $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') @('ProgramMenuFolder', 'TARGETDIR', '.')
    Insert-MsiRow $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') @('KeliProgramMenuFolder', 'ProgramMenuFolder', 'Keli')

    Insert-MsiRow $database 'Component' @('Component', 'ComponentId', 'Directory_', 'Attributes', 'Condition', 'KeyPath') @('KeliDesktopComponent', $ComponentCode, 'INSTALLFOLDER', 256, $null, 'KeliDesktopShellExe')
    Insert-MsiRow $database 'Feature' @('Feature', 'Feature_Parent', 'Title', 'Description', 'Display', 'Level', 'Directory_', 'Attributes') @('KeliDesktopFeature', $null, 'Keli Desktop', 'Keli Desktop MVP client', 1, 1, 'INSTALLFOLDER', 0)
    Insert-MsiRow $database 'FeatureComponents' @('Feature_', 'Component_') @('KeliDesktopFeature', 'KeliDesktopComponent')

    $shell = Get-Item -LiteralPath (Join-Path $StageDir 'keli-desktop-shell.exe')
    $readme = Get-Item -LiteralPath (Join-Path $StageDir 'README.txt')
    $manifest = Get-Item -LiteralPath (Join-Path $StageDir 'keli-desktop-manifest.json')
    Insert-MsiRow $database 'File' @('File', 'Component_', 'FileName', 'FileSize', 'Version', 'Language', 'Attributes', 'Sequence') @('KeliDesktopShellExe', 'KeliDesktopComponent', 'keli-desktop-shell.exe', [int]$shell.Length, $Version, $null, 512, 1)
    Insert-MsiRow $database 'File' @('File', 'Component_', 'FileName', 'FileSize', 'Version', 'Language', 'Attributes', 'Sequence') @('KeliDesktopReadme', 'KeliDesktopComponent', 'README.txt', [int]$readme.Length, $null, $null, 512, 2)
    Insert-MsiRow $database 'File' @('File', 'Component_', 'FileName', 'FileSize', 'Version', 'Language', 'Attributes', 'Sequence') @('KeliDesktopManifest', 'KeliDesktopComponent', 'keli-desktop-manifest.json', [int]$manifest.Length, $null, $null, 512, 3)

    Insert-MsiRow $database 'Media' @('DiskId', 'LastSequence', 'DiskPrompt', 'Cabinet', 'VolumeLabel', 'Source') @(1, 3, $null, '#keli-desktop.cab', $null, $null)
    Insert-MsiRow $database 'Shortcut' @('Shortcut', 'Directory_', 'Name', 'Component_', 'Target', 'Arguments', 'Description', 'Hotkey', 'Icon_', 'IconIndex', 'ShowCmd', 'WkDir') @('KeliDesktopShortcut', 'KeliProgramMenuFolder', 'Keli', 'KeliDesktopComponent', '[#KeliDesktopShellExe]', $null, 'Keli Desktop', $null, $null, $null, 1, 'INSTALLFOLDER')

    Add-StandardSequences -Database $database
    Add-MsiStream -Installer $installer -Database $database -Name 'keli-desktop.cab' -Path $cabPath
    $database.Commit()
    [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}

function Write-MsiSmoke {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MsiPath,

        [Parameter(Mandatory = $true)]
        [string]$SmokePath,

        [Parameter(Mandatory = $true)]
        [string]$AdminExtractDir
    )

    if (!(Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
        throw "MSI was not produced: $MsiPath"
    }

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($MsiPath, 0)
    $productName = Get-MsiScalar $database "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductName'"
    $upgradeCode = Get-MsiScalar $database "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='UpgradeCode'"
    $nativeCoreDefault = Get-MsiScalar $database "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='NativeCoreDefault'"
    $fileCount = Get-MsiCount $database 'SELECT `File` FROM `File`'
    $shortcutCount = Get-MsiCount $database "SELECT ``Shortcut`` FROM ``Shortcut`` WHERE ``Shortcut``='KeliDesktopShortcut'"
    $mediaCabinet = Get-MsiScalar $database 'SELECT `Cabinet` FROM `Media` WHERE `DiskId`=1'
    $streamCount = Get-MsiCount $database "SELECT ``Name`` FROM ``_Streams`` WHERE ``Name``='keli-desktop.cab'"

    $productName = ([string]$productName).Trim()
    $upgradeCode = ([string]$upgradeCode).Trim()
    $nativeCoreDefault = ([string]$nativeCoreDefault).Trim()
    $mediaCabinet = ([string]$mediaCabinet).Trim()
    $fileCount = [int]([string]$fileCount).Trim()
    $shortcutCount = [int]([string]$shortcutCount).Trim()
    $streamCount = [int]([string]$streamCount).Trim()

    if ($productName -ne 'Keli Desktop MVP') {
        throw "MSI ProductName mismatch: $productName"
    }
    if ($upgradeCode -ne $UpgradeCode) {
        throw "MSI UpgradeCode mismatch: $upgradeCode"
    }
    if ($nativeCoreDefault -ne 'true') {
        throw "MSI NativeCoreDefault mismatch: $nativeCoreDefault"
    }
    if ($fileCount -ne 3) {
        throw "MSI file count mismatch: $fileCount"
    }
    if ($shortcutCount -ne 1) {
        throw "MSI shortcut count mismatch: $shortcutCount"
    }
    if ($mediaCabinet -ne '#keli-desktop.cab') {
        throw "MSI cabinet mismatch: $mediaCabinet"
    }
    if ($streamCount -ne 1) {
        throw "MSI embedded cabinet stream missing"
    }

    if (Test-Path -LiteralPath $AdminExtractDir) {
        Remove-Item -LiteralPath $AdminExtractDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $AdminExtractDir | Out-Null
    $adminLog = Join-Path (Split-Path -Parent $AdminExtractDir) 'desktop-msi-admin-smoke.log'
    $admin = Start-Process msiexec.exe -ArgumentList @(
        '/a',
        $MsiPath,
        '/qn',
        "TARGETDIR=$AdminExtractDir",
        '/L*v',
        $adminLog
    ) -Wait -PassThru
    if ($admin.ExitCode -ne 0) {
        throw "MSI administrative extraction failed with exit code $($admin.ExitCode): $adminLog"
    }
    $extractedFiles = @(
        (Join-Path $AdminExtractDir 'Keli\keli-desktop-shell.exe'),
        (Join-Path $AdminExtractDir 'Keli\README.txt'),
        (Join-Path $AdminExtractDir 'Keli\keli-desktop-manifest.json')
    )
    foreach ($path in $extractedFiles) {
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "MSI administrative extraction missing file: $path"
        }
    }
    $extractedReadme = Join-Path $AdminExtractDir 'Keli\README.txt'
    $extractedManifestPath = Join-Path $AdminExtractDir 'Keli\keli-desktop-manifest.json'
    Require-FileContains -Path $extractedReadme -Text 'Import a subscription URL or local subscription config.'
    $extractedManifest = Get-Content -Raw -LiteralPath $extractedManifestPath | ConvertFrom-Json
    foreach ($case in @('open-desktop-shell', 'import-subscription', 'select-node', 'start-stop-system-proxy', 'tun-preflight', 'export-support-bundle')) {
        Require-ManifestSmokeCase -Manifest $extractedManifest -Name $case
    }

    $result = [ordered]@{
        status = 'passed'
        msi = 'target\desktop\keli-desktop-mvp-windows-x64.msi'
        native_core_default = $true
        file_count = $fileCount
        shortcut = 'ProgramMenuFolder\Keli\Keli.lnk'
        admin_extract = 'target\desktop-msi-admin-smoke'
        readme_subscription_import = 'subscription-url-or-config'
        manual_smoke_cases = $extractedManifest.manual_smoke
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $SmokePath -Encoding ASCII
}

$repoRoot = Resolve-RepoRoot
$stageDir = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64'
$msiPath = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64.msi'
$smokePath = Join-Path $repoRoot 'target\desktop\keli-desktop-msi-smoke.json'
$adminExtractDir = Join-Path $repoRoot 'target\desktop-msi-admin-smoke'
$version = Get-WorkspaceVersion -CargoToml (Join-Path $repoRoot 'Cargo.toml')

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'input target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe'
        Write-Output 'input target\desktop\keli-desktop-mvp-windows-x64\README.txt'
        Write-Output 'input target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json'
        Write-Output 'msi target\desktop\keli-desktop-mvp-windows-x64.msi'
        Write-Output 'metadata native_core_default true'
        Write-Output "metadata upgrade_code $UpgradeCode"
        Write-Output 'shortcut ProgramMenuFolder\Keli\Keli.lnk'
        Write-Output 'admin_extract target\desktop-msi-admin-smoke'
        Write-Output 'admin_extract readme import-subscription-url-or-config'
        Write-Output 'admin_extract manifest manual_smoke import-subscription'
        Write-Output 'smoke target\desktop\keli-desktop-msi-smoke.json'
        return
    }

    Write-DesktopMsi -StageDir $stageDir -MsiPath $msiPath -Version $version
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 200
    Write-MsiSmoke -MsiPath $msiPath -SmokePath $smokePath -AdminExtractDir $adminExtractDir
    Write-Host "Desktop MSI created: $msiPath"
    Write-Host "Desktop MSI smoke passed: $smokePath"
} finally {
    Pop-Location
}

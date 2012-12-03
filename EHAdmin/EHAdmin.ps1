[xml]$xaml= Get-Content 'C:\Users\Public\Documents\Visual Studio 2012\WpfApplication1\WpfApplication1\EHAdmin.xaml'
if ( ( Get-PSProvider | WHERE Name -eq 'SQLSERVER' ) -eq $null )
{ 
    Write-Warning 'Loading "sqlps" module. This takes a minute...'
    Import-Module 'sqlps' -DisableNameChecking 
}

$window = New-Object System.Windows.Window
$window.Title = 'EHAdmin.ps1'
$window.SizeToContent = 'WidthAndHeight'
$window.Topmost = $true

$reader = New-Object System.Xml.XmlNodeReader $xaml 
$page = [Windows.Markup.XamlReader]::Load($reader) 

$endpoints = $page.FindName('endpoints')
$smoHub = New-Object Microsoft.SqlServer.Management.Smo.Server
$hubList = $endpoints.FindName('hubEndpoint')
$hubInstances = $hubList.FindName('hubInstances')
$hubDatabases = $hubList.FindName('hubDatabases')

$smoSpoke = New-Object Microsoft.SqlServer.Management.Smo.Server
$spokeList = $endpoints.FindName('spokeEndpoint')
$spokeInstances = $spokeList.FindName('spokeInstances')
$spokeDatabases = $spokeList.FindName('spokeDatabases')
$spokeExportPath = $spokeList.FindName('spokeExportPath')
$browseForFolder = $spokeList.FindName('browseForFolder')
$spokeDSNToHub = $spokeList.FindName('spokeDSNToHub')

$spokeBackupPhrases = $spokeList.FindName('spokeBackupPhrases')
$securityList = $page.FindName('securityList')
$cryptographyList = $page.FindName('cryptographyList')
$schemaList = $page.FindName('schemaList')

#toolbars
$action = $page.FindName('action')
$targetType = $action.FindName('targetType')
$environment = $action.FindName('environment')
$pSDebug = $action.FindName('pSDebug')

#toolbar-options-radiobuttons
$option = $action.FindName('option')
$eHAdmin = $option.FindName('eHAdmin')
$install = $option.FindName('install')
$remove = $option.FindName('remove')

#toolbar-targettype-radiobuttons
$hub = $targetType.FindName('hub') 
$spoke = $targetType.FindName('spoke') 

#toolbar-environment-radiobuttons
$test = $Environment.FindName('test')
$live = $Environment.FindName('live')

#toolbar-options-events
$eHAdmin.add_Click(
{ 
    $hubList.IsEnabled = $false
    $spokeList.IsEnabled = $true
    $targetType.Visibility = 'Collapse' 
} )
$install.add_Click(
{ 
    $hubList.IsEnabled = $true
    $spokeList.IsEnabled = $false
    $targetType.Visibility = 'Visible' 
} )
$remove.add_Click(
{ 
    $hubList.IsEnabled = $true
    $spokeList.IsEnabled = $true
    $targetType.Visibility = 'Visible' 
} )

#toolbar-targettype-radiobuttons-events
$hub.add_Click( 
{ 
    $environment.Visibility = 'Visible'
} )
$spoke.add_Click(
{ 
    $environment.Visibility = 'Visible'
} )

#toolbar-environment-radiobuttons-events
$test.add_Click(
{
    $pSDebug.Visibility = "Visible"
})
$live.add_Click(
{
    $pSDebug.Visibility = "Collapsed"
})

#toolbar-PSDebug-$DebugPreference
$dbgPreference = $PSDebug.FindName('debugPreference')
foreach($pref in [System.Management.Automation.ActionPreference].GetEnumValues()) 
{$null = $dbgPreference.Items.Add($pref)}
$dbgPreference.SelectedItem = $DebugPreference

#toolbar-PSDebug-[Set-PSDebug]
$step = $pSDebug.FindName('step')
$step.IsChecked = $false
$strict = $pSDebug.FindName('strict')
$strict.IsChecked = $true
$trace = $pSDebug.FindName('trace')
$null = $trace.Items.Add(0)
$null = $trace.Items.Add(1)
$null = $trace.Items.Add(2)
$trace.SelectedItem = 0

#Listview events
Get-ChildItem -Path SQLSERVER:\SQL -Name | Sort-Object | ForEach-Object { $null = $hubInstances.Items.Add( $_ ) }
$hubInstances.Add_SelectionChanged( 
{     
    Set-Variable -Name $smoHub -Scope script -Value { New-Object Microsoft.SqlServer.Management.Smo.Server( $hubInstance.SelectedItem ) }         
    foreach( $database in $smoHub.Databases ) { $null = $hubDatabases.Items.Add( $database ) } 
    $null = $hubDatabases.Items.Add( 'ehHub' )
    $hubDatabases.SelectedItem = 'ehHub'
    $hubList.IsEnabled = $false
    #if ( $spokeList.IsEnabled ) 
} )

Get-ChildItem -Path SQLSERVER:\SQL -Name | Sort-Object | ForEach-Object { $null = $spokeInstances.Items.Add( $_ ) }
$SpokeInstances.Add_SelectionChanged( 
{     
    Set-Variable -Name $smoSpoke -Scope script -Value { New-Object Microsoft.SqlServer.Management.Smo.Server( $spokeInstance.SelectedItem ) }         
    foreach( $database in $smoSpoke.Databases ) { $null = $spokeDatabases.Items.Add( $database ) } 
    $null = $spokeDatabases.Items.Add( 'ehdb' )
    $spokeDatabases.SelectedItem = 'ehdb'
} )

$browseForFolder.add_Click(
{ 
    $comWindow = New-Object Windows.Interop.WindowInteropHelper($window)
    $msg = 'Select a folder for export of key and certificate backups.'
    $object = New-Object -comObject Shell.Application
    $folder = $object.BrowseForFolder($comWindow.Handle, $msg, 0, 'ssfCOMPUTER')
    if ($folder -ne $null) { $spokeExportPath.Text = $folder.self.Path }    
} )

#enum algorithms

$SMKAlgorithms =  [Microsoft.SqlServer.Management.Smo.SymmetricKeyEncryptionAlgorithm].GetEnumValues()

$DEKAlgorithms = [Microsoft.SqlServer.Management.Smo.DatabaseEncryptionAlgorithm].GetEnumValues()

#don't see an enum for the T-SQL HASHBYTES() algorithms? must be somewhere other than BOL...
$hashAlgorithms = @( 'MD2','MD4','MD5','SHA','SHA1','SHA2_256','SHA2_512' ) 

## beginning state
$spokeBackupPhrases.Visibility='Collapsed'
$securityList.Visibility='Collapsed'
$cryptographyList.Visibility='Collapsed'
$schemaList.Visibility='Collapsed'

$targetType.Visibility='Collapsed'
$environment.Visibility='Collapsed'
$pSDebug.Visibility='Collapsed'

$eHAdmin.IsChecked = $true
$hubList.IsEnabled = $false
$spokeList.IsEnabled = $true

$spokeDSNToHub.Text = 'Hub'

$window.AddChild($page)
$window.ShowDialog()

# 
switch ($option.Items) 
{
    'ehAdmin'
    {
        # interactive key admin tool workflows here
        # backup a key/cert
        # define and schedule backup sets
        # restore a key/cert
        # re-key and regen a hierarchy
    }
    'install'
    {
        # background topology deployment workflows here
    
        if ( $test.IsChecked ) 
        {
            $DebugPreference = $PSDebug.FindName('debugPreference').SelectedItem
            if ( $step.IsChecked ) { Set-PSDebug -Step }
            if ( $strict.IsChecked ) { Set-PSDebug -Strict }
            Set-PSDebug -Trace $PSDebug.FindName('trace').SelectedItem 

            $WITH_OPTIONS =  'WITH EXECUTE AS CALLER'
        }
        else #live
        { 
            $DebugPreference = 'SilentlyContinue' 
            Set-PSDebug -Off
     
            $WITH_OPTIONS =  'WITH EXECUTE AS CALLER, ENCRYPTION'
            #Microsoft.SqlServer.Management.Smo.ExecutionContext = 'ExecuteAsPrincipal'
            #Microsoft.SqlServer.Management.Smo.ExecutionPrincipal = 'Caller'
            #Microsoft.SqlServer.Management.Smo.IsEncrypted = $true
        }

        $HUB_SQL_INSTANCE = $hubInstances.SelectedItem
        $HUB_DATABASE = $hubDatabases.SelectedItem
        $SPOKE_SQL_INSTANCE = $spokeInstances.SelectedItem
        $SPOKE_DATABASE = $spokeDatabases.SelectedItem
        $EXPORT_PATH = $spokeExportPath.Text
        $HUB_DATASOURCE = $spokeDSNToHub.Text

        Add-OdbcDsn $HUB_DATASOURCE -DriverName "SQL Server Native Client 11.0" -DsnType System 
            -SetPropertyValue @("Server=$HUB_SQL_INSTANCE", "Database=$HUB_DATABASE")

        #test dsn?


        if ( (Test-Path $profile.AllUsersCurrentHost) -eq $false )
        {
            New-Item -Path $profile.AllUsersCurrentHost -Itemtype file -Force 
        }
        $hostProfile = $profile.AllUsersCurrentHost 
        '$HUB_SQL_INSTANCE="{0}"' -f  $HUB_SQL_INSTANCE >> $hostProfile
        '$HUB_DATABASE="{0}"' -f $HUB_DATABASE >> $hostProfile
        '$SPOKE_SQL_INSTANCE="{0}"' -f $SPOKE_SQL_INSTANCE >> $hostProfile
        '$SPOKE_DATABASE="{0}"' -f $SPOKE_DATABASE >> $hostProfile
    }
    'remove'
    {
        # remove and clean a topology node here
        #drop a spoke
        #drop hub 
        
    }
}


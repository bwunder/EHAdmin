cls
Import-Module "sqlps" -DisableNameChecking

# for testing/development/debugging 
function Decode-SecureString 
{   
    [CmdletBinding( PositionalBinding=$true )]
    [OutputType( [String] )]
    param ( [Parameter( Mandatory=$true, ValueFromPipeline=$true )]
            [System.Security.SecureString] $secureString )  
    begin 
    { $marshal = [System.Runtime.InteropServices.Marshal] }
    process 
    { $BSTR = $marshal::SecureStringToBSTR($secureString )
     $marshal::PtrToStringAuto($BSTR) } 
    end
    { $marshal::ZeroFreeBSTR($BSTR) }
}

function Test-EHSecureString 
{   
    [CmdletBinding( PositionalBinding=$true )]
    [OutputType( [Boolean] )]
    param ( [Parameter( Mandatory=$true, ValueFromPipeline=$true )] 
            [System.Security.SecureString] $secureString
          , [Int32] $minLength = 14 
          , [Int32] $minScore = 3 )  
    begin 
    { 
        $marshal = [System.Runtime.InteropServices.Marshal] 
    }
    process 
    {   # need the var to zero & free unencrypted copy of secret
        [Int16] $score = 0
        $BSTR = $marshal::SecureStringToBSTR($secureString)
        if ( $marshal::PtrToStringAuto($BSTR).length -ge $minLength )
        { 
            switch -Regex ( $( $marshal::PtrToStringAuto($BSTR) ) )
            {
                '[#,.;:\\]+?' { Write-Warning ( 'character: {0}' -f $Matches[0] ); Break }
                '(DROP|ADD|CREATE|SELECT|INSERT|UPDATE|DELETE|GRANT|REVOKE|RUNAS|ALTER)+?' 
                              { Write-Warning ( 'SQL command: {0}' -f $Matches[0] ); Break }
                '(AUX|CLOCK|COM[1-8]|CON|LPT[1-8]|NUL|PRN)+?' 
                              { Write-Warning ( 'dos command: {0}' -f $Matches[0] ); Break } 
                '(--|\*\/|\/\*)+?' { Write-Warning ( 'comment: {0}' -f $Matches[0] ); Break }
                '(?-i)[a-z]'  { $score+=1 }
                '(?-i)[A-Z]'  { $score+=1 }
                '\d+?'        { $score+=1 }
                '\S\W+?'      { $score+=1 }
                Default { Write-Warning $switch.current; Break }        
            } 
        }
        else
        { write-warning ( 'length: {0}' -f $( $marshal::PtrToStringAuto($BSTR).length ) ) } 
        write-warning ( 'score: {0}' -f $score )  
        $( $score -ge $minScore )
    }        
    end { $marshal::ZeroFreeBSTR($BSTR) }
}

Test-EHSecureString $( ConvertTo-SecureString '1Qa@wSdE3$rFgT'  -AsPlainText -Force ) 



function Get-ChildFromList 
    {   # current location is implicit parameter
        [CmdletBinding()]
        [OutputType( [string] )]
        [Parameter( Mandatory = $true, ValueFromPipeline = $true )]
        param ( [string] $defaultItem )      
        begin 
        { 
            $defaultListItem = 'use textbox value...'                        

            $objForm = New-Object System.Windows.Forms.Form 
            $objForm.Size = New-Object System.Drawing.Size(300,340) 
            $objForm.StartPosition = "CenterScreen"
            $objForm.Text = "Select Child Item"
            $objForm.KeyPreview = $True
            $objForm.Add_KeyDown(
                {
                    if ( $_.KeyCode -eq "Enter" ) 
                        { $objForm.DialogResult = 'OK' }
                } )
            $objForm.Add_KeyDown(
                {
                    if ($_.KeyCode -eq "Escape") 
                        { DialogResult = 'Cancel' }
                } )

            $objListLabel = New-Object System.Windows.Forms.Label
            $objListLabel.Location = New-Object System.Drawing.Size(10,0) 
            $objListLabel.Size = New-Object System.Drawing.Size(260,50) 
            $objListLabel.Text = ('Path : [{0}]' -f $( Get-Location | Convert-Path ) )
            $objListLabel.TextAlign = "MiddleLeft" 

            $objForm.Controls.Add( $objListLabel )  

            $objListBox = New-Object System.Windows.Forms.ListBox 
            $objListBox.Location = New-Object System.Drawing.Size(10,50) 
            $objListBox.Size = New-Object System.Drawing.Size(260,20) 
            $objListBox.Height = 140
            $objListBox.BeginUpdate()       
            [void] $objListBox.Items.Add( $defaultListItem )
            Get-ChildItem -Name | Sort-Object | ForEach-Object { [void] $objListBox.Items.Add( $_ ) }
            $objListBox.EndUpdate()
            $objForm.Controls.Add( $objListBox ) 

            $objBoxLabel = New-Object System.Windows.Forms.Label
            $objBoxLabel.Location = New-Object System.Drawing.Size(20,200) 
            $objBoxLabel.Size = New-Object System.Drawing.Size(260,30) 
            $objBoxLabel.Text = 'Edit textbox or hit OK to accept default.'
            $objBoxLabel.Text += "`r`n"
            $objBoxLabel.Text += "Used only when '$defaultListItem' selected."
            $objForm.Controls.Add( $objBoxLabel ) 

            $objTextBox = New-Object System.Windows.Forms.TextBox
            $objTextBox.Location = New-Object System.Drawing.Size(20,230)
            $objTextBox.Size = New-Object System.Drawing.Size(240,20) 
            $objTextBox.Text = $defaultItem
            $objForm.Controls.Add($objTextBox) 

            $OKButton = New-Object System.Windows.Forms.Button
            $OKButton.Location = New-Object System.Drawing.Size(160,270)
            $OKButton.Size = New-Object System.Drawing.Size(50,23)
            $OKButton.Text = "OK"
            $OKButton.Add_Click( { $objForm.DialogResult = 'OK' } )
            $objForm.Controls.Add($OKButton)

            $CancelButton = New-Object System.Windows.Forms.Button
            $CancelButton.Location = New-Object System.Drawing.Size(220,270)
            $CancelButton.Size = New-Object System.Drawing.Size(50,23)
            $CancelButton.Text = "Cancel"
            $CancelButton.Add_Click( { $objForm.DialogResult = 'Cancel' } )
            $objForm.Controls.Add($CancelButton)

            $objForm.Topmost = $true 
            $objForm.Add_Shown( { $objForm.Activate() } )
            [void] $objForm.ShowDialog()
        }
    
        process 
        { 
            if ( $objForm.DialogResult -eq 'OK' -and $objListBox.SelectedItems.Count -eq 1 )
                { 
                    $( if ( $objListBox.SelectedItem -eq $defaultListItem ) 
                        { $objTextBox.Text }
                        else 
                        { $objListBox.SelectedItem } )
                    $objForm.Close() 
                }
             if ( $objForm.DialogResult -eq 'Cancel') { $objForm.Close() }
        }  
    }
        

try
    { 
        Set-Location SQLSERVER:\SQL
        $hubInstance = $( Get-ChildFromList( $env:COMPUTERNAME ) )
        $smoHubSrv = New-Object Microsoft.SqlServer.Management.Smo.Server( $hubInstance )
        if ( $smoHubSrv.Configuration.ContainmentEnabled.RunValue -eq 0 )
        {
            $smoHubSrv.Configuration.ContainmentEnabled.ConfigValue = 1
            $smoHubSrv.Configuration.Alter()
        }
        Set-Location ( '{0}\Databases' -f $( if ($hubInstance -match '\\' ) 
                                            { $hubInstance } else { "$hubInstance\DEFAULT" } ) )
        $hubDatabase = Get-ChildFromList( 'ehHub' ) 
        if ( ! $smoHubSrv.Databases.Contains( $hubDatabase ) ) 
        {   
            $smoHubDB = New-Object Microsoft.SqlServer.Management.Smo.Database
            $smoHubDB.Parent = $smoHubSrv
            $smoHubDB.Name = $hubDatabase
            $smoHubDB.ContainmentType = 'Partial' 
            $smoHubDB.DatabaseOptions.DatabaseOwnershipChaining = $false
            $smoHubDB.DatabaseOptions.Trustworthy = $false
            $smoHubDB.Create()
            $smoHubDB.SetOwner( $( 'sa')  ) 
        }
        Set-Location $hubDatabase          
        if ( $( Read-Host "Evaluation mode (use default pass phrases)? y or n [n]" ) -ieq 'y' )
        { 
            $HUB_ADMIN_PASSWORD      = $( ConvertTo-SecureString 'si*%tPW#4RfHgd'  -AsPlainText -Force ) 
            $HUB_ODBC_AGENT_PASSWORD = $( ConvertTo-SecureString 'VerifyDSN1'      -AsPlainText -Force )
            $SPOKE_ADMIN_PASSWORD    = $( ConvertTo-SecureString 'sj*%tFE#4RfHgf'  -AsPlainText -Force )
            $SPOKE_BROKER_PASSWORD   = $( ConvertTo-SecureString 'sk*%tFE#4RfHge'  -AsPlainText -Force )
        } 
         else
        { 
            do { $HUB_ADMIN_PASSWORD = $( Read-Host 'HUB_ADMIN_PASSWORD?' -AsSecureString ) }
            until ( $(Test-EHSecureString $HUB_ADMIN_PASSWORD ) )                                
            # this one never passed through the CheckPhrase T-SQL function so not tested here 
            do { $HUB_ODBC_AGENT_PASSWORD = Read-Host 'HUB_ODBC_AGENT_PASSWORD?' -AsSecureString } 
            until ( $HUB_ODBC_AGENT_PASSWORD.Length > 0 )
            do { $SPOKE_ADMIN_PASSWORD = Read-Host 'SPOKE_ADMIN_PASSWORD?' -AsSecureString } 
            until ( Test-SecureStringHardness $SPOKE_ADMIN_PASSWORD ) 
            do { $SPOKE_BROKER_PASSWORD = Read-Host 'SPOKE_BROKER_PASSWORD?' -AsSecureString } 
            until ( Test-SecureStringHardness $SPOKE_BROKER_PASSWORD )
        }  
        Set-Location 'Users' 
        if ( $( Get-ChildItem -Name) -notcontains 'HubAdmin' )
        {
            $HubAdmin = New-Object Microsoft.SqlServer.Management.Smo.User
            $HubAdmin.Parent = $smoHubDB
            $HubAdmin.Name = 'HubAdmin'     
            $HubAdmin.Create( $HUB_ADMIN_PASSWORD ) 
        } 

        if ( $( Get-ChildItem -Name ) -notcontains 'HubAgent' )   
        {
            $HubAdmin = New-Object Microsoft.SqlServer.Management.Smo.User
            $HubAdmin.Name = 'HubAgent'     
            $HubAdmin.Parent = $smoHubDB
            $HubAdmin.Create( $HUB_ODBC_AGENT_PASSWORD ) 
        }

        if ( $( Get-ChildItem -Name ) -notcontains 'SpokeAdmin' )   
        {
            $HubAdmin = New-Object Microsoft.SqlServer.Management.Smo.User
            $HubAdmin.Name = 'SpokeAdmin'     
            $HubAdmin.Parent = $smoHubDB
            $HubAdmin.Create( $SPOKE_ADMIN_PASSWORD ) 
        }

        if ( $( Get-ChildItem -Name ) -notcontains 'SpokeBroker' )   
        {
            $HubAdmin = New-Object Microsoft.SqlServer.Management.Smo.User
            $HubAdmin.Name = 'SpokeBroker'     
            $HubAdmin.Parent = $smoHubDB
            $HubAdmin.Create( $SPOKE_BROKER_PASSWORD ) 
        }

# can be decoded but once executed the clear text can be discovered in memory
Decode-SecureString $HUB_ADMIN_PASSWORD | Write-Warning
Decode-SecureString $HUB_ODBC_AGENT_PASSWORD | Write-Warning
Decode-SecureString $SPOKE_ADMIN_PASSWORD | Write-Warning
Decode-SecureString $SPOKE_BROKER_PASSWORD | Write-Warning

        Invoke-Sqlcmd -AbortOnError -Database 'master' `
           -OutputSqlErrors $true -ServerInstance $hubInstance `
           -InputFile C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\HubInstallSQL.sql
    }
# else 
#    {         
#Set-Location SQLSERVER:\SQL
#$hubInstance =  Get-ChildFromList( $env:COMPUTERNAME )
#            Invoke-Sqlcmd -AbortOnError -Database 'master' -OutputSqlErrors 1 -ServerInstance $hubInstance -InputFile C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\HubUninstallSQL.sql
#    }
#}         
catch 
    { $StackTrace;    throw }

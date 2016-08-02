<# agree on a convention for error codes
# thoughts
#  0 - success
#  1 - invalid cert (expired / name mismatch)
#  3 - no cert available to enable https
#  4 - some other error

v 2.0 - add logic to renew a cert 
 #>

#region setup logging 
function Write-Log {
    param(
        [int]$ErrorLevel=1, # 1 - info, 2 - warning, 3 - error
        [Parameter(position=1,ValueFromPipeline=$true)][string]$Msg,
        [Parameter(position=2)][string]$Component, # source of the entry
        [Parameter(position=3)][string]$LogFile = "c:\temp\LPUlog.log",
        [switch]$break,
        [switch]$tee

    )

    if( !$Component ){ $Component = $PSCommandPath -replace '^.*\\|\.[^\.]*$' } # script name
    if( !$LogFile ){ $LogFile = $PSCommandPath -replace '\.ps1$','.log' } # <ScriptRoot>\<ScriptName>.log
    if($break){$Msg='#############################################################'}
    if($tee){Write-Output $msg}
    $TZBias = (Get-WmiObject Win32_TimeZone).bias
    $Time = "$(Get-Date -Format 'HH:mm:ss.fff')$TZBias"
    $Date = Get-Date -Format 'MM-dd-yyyy'
    $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    $LogEntry = "<![LOG[$Msg]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"$Context`" type=`"$ErrorLevel`" thread=`"$pid`" file=`"`">"
   
    Add-Content -Path $LogFile -Value $LogEntry
    
} 
#endregion

#check if listener already exists
$listener = dir WSMan:\localhost\Listener | Where Keys -like *https* 

if ($listener){
    #Listener already exists, verify it's using the right cert, and the longest possible cert

    #Resolve the HTTPs listener name
    $ListenerName = dir WSMan:\localhost\Listener | Where Keys -like *https* | select -expand Name

    #Get the WINRM HTTPS listener certificate thumbprint
    $CertThumbprt =  get-childitem "WSMan:\localhost\Listener\$ListenerName" | Where Name -like "CertificateThumbprint" |select -ExpandProperty Value

    #Compare that to our longest cert...
        
    #grabs the longest lasting cert availble for SSL 
    $longestCert = dir cert:\localmachine\My | Where EnhancedKeyUsageList -like *Server*  | Where Subject -like *$env:COMPUTERNAME* | sort NotAfter -Descending | Select -ExpandProperty ThumbPrint

    write-log "is the current cert for ssl the longest one available ? $($longestCert -eq $CertThumbprt)" -tee

    #Are we using the longest cert we could?  If so, we've got nothing to do, time to quit
    If ($longestCert -eq $CertThumbprt){
        #we're done
        Write-log "This machine is using the longest possible cert for SSL, exiting with errorlevel 0..." -tee
        exit 0 
    }

    #Is $CertThumbPrt or $LongestCert actually nonexistant?
    if (($longestCert -eq $null) ) {
        #! Error condition: listener is enabled, but not using a valid cert
        Write-log "!error condtion: This machine doesn't have a valid cert anymore (maybe it changed names or domains?) errorlevel 1 ..." -tee
        exit 1 

        #later : try to renew a cert 
                
    }

    #Do we have a longer cert available and we're not using it?  Lets fix that
    If ($longestCert -ne $CertThumbprt){
        
        $certpath =  get-childitem "WSMan:\localhost\Listener\$ListenerName" | Where Name -like "CertificateThumbprint" 
        Set-Item -Path $certpath\CertificateThumbprint -Value 'THUMBPRINT';
        
    }

}
else{
    #if no listener...
    
    #attempts to find a certificate suitable for Client Authentication for this system, and picks the one with the longest date
    $longestCert = dir cert:\localmachine\My | Where EnhancedKeyUsageList -like *Server*  | Where Subject -like *$env:COMPUTERNAME* | sort NotAfter -Descending | Select -ExpandProperty ThumbPrint

    #region errorconditions 
        #if longestCert is empty, then we can't setup a listener, lets #exit
        If ($longestCert -eq $null){
            Write-Log -Msg "!error condition: no valid cert to enable a listener (no cert or name mismatch), #exiting with errorlevel 3" -tee 
            exit 3
        }
    
        #cert has expired
        if ($longestcert.NotAfter -le (Get-Date)){
            #! error condition: Certificate has expired 
            Write-Log -Msg "!error condition: The only cert available has expired, #exiting with errorlevel 1" -tee 
        
            #Renew cert steps go here
            exit 1 
        }
    #endregion

    #We have a valid cert, enabling winrm over https (tl: can't contain the output of this command below if it errors, sadly)
    Invoke-expression "winrm quickconfig -transport:https -force" -ErrorVariable winRMerror | Out-Null
    if ($WinrmError){
       #! error condition: winrm quickconfig failed for some reason
       Write-log "!error condition: winrm quickconfig failed for some reason, #exiting w/ errorlevel 4" -tee
       Write-log "!error text $WinrmError"
       exit 4 
    }

    #We need to create a service record to tell the domain we're listneing on https, let's do that below    
    $fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
    $SPNoutput = Invoke-Expression "setspn -S HTTPS/$fqdn $($env:COMPUTERNAME)" -ErrorVariable spnerror 
    
    
    #test for https record in output of prev cmd
    if ($out = $SPNoutput | select-string HTTPS) {
        write-log "success!  SPN seems to have been created, output [$($out.ToString().Trim())]" -tee
        Write-Log "output from SPN command $SPNoutput"
        exit 0
    }else{
        write-log "!error condition: failed to create SPN! output [$SPNoutput] error [$SPNerror]" -tee
        write-log "!error condition: exiting with errorlevel 4" -tee
        exit 4
    }


}

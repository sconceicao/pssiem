$ErrorActionPreference = "SilentlyContinue"

Function Parse-Event {
    # Credit: https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-WinEventData.ps1
    param(
        [Parameter(ValueFromPipeline=$true)] $Event
    )

    Process
    {
        foreach($entry in $Event)
        {
            $XML = [xml]$entry.ToXml()
            $X = $XML.Event.EventData.Data
            For( $i=0; $i -lt $X.count; $i++ ){
                $Entry = Add-Member -InputObject $entry -MemberType NoteProperty -Name "$($X[$i].name)" -Value $X[$i].'#text' -Force -Passthru
            }
            $Entry
        }
    }
}

Function Write-Alert ($alerts) {
    echo "Date: $($alerts.Date)"
    echo "Type: $($alerts.Type)"
    
    $alerts.Remove("Type")
    $alerts.Remove("Date")

    foreach($alert in $alerts.GetEnumerator()) {
        echo "$($alert.Name): $($alert.Value)"
    }
    write-host "-----"
}

ipmo "C:\Users\Public\Documents\Functions-PSStoredCredentials.ps1"
$KeyPath = "C:\Sistemas\Cred\"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogName = "Microsoft-Windows-Sysmon"
$server = "DNS-AZURE"
$checklist = [IO.File]::ReadLines("C:\Users\Public\Documents\checklist.txt") |?{!([string]::IsNullOrWhitespace($_))}
$blacklist = [IO.File]::ReadLines("C:\Users\Public\Documents\blacklist.txt") |?{!([string]::IsNullOrWhitespace($_))}

$maxRecordId = (Get-WinEvent -Provider $LogName -max 1).RecordID

while ($true)
{
    Start-Sleep 1

    $xPath = "*[System[EventRecordID > $maxRecordId]]"
    $logs = Get-WinEvent -Provider $LogName -FilterXPath $xPath | Sort-Object RecordID

    foreach ($log in $logs) {
        $evt = $log | Parse-Event
        if ($evt.id -eq 1) {
            $output = @{}
            $output.add("Type", "Process Create")
            $output.add("Date", $evt.TimeCreated)
            $output.add("PID", $evt.ProcessId)
            $output.add("Image", $evt.Image)
            $output.add("CommandLine", $evt.CommandLine)
            $output.add("CurrentDirectory", $evt.CurrentDirectory)
            $output.add("User", $evt.User)
            $output.add("ParentImage", $evt.ParentImage)
            $output.add("ParentCommandLine", $evt.ParentCommandLine)
            $output.add("ParentUser", $evt.ParentUser)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log


            #RULES

            If(([io.fileinfo]$evt.Image).basename -in $checklist -and ([io.fileinfo]$evt.ParentImage).basename -notin $blacklist) {
                       
        $sub = ([io.fileinfo]$evt.Image).name
        Send-MailMessage -From sandro.conceicao@bravantic.com -To sandro.conceicao@bravantic.com -Subject "IOC $server $sub"  -Body $evt.Message -SmtpServer smtp.office365.com -Credential (Get-StoredCredential -username sandro.conceicao@bravantic.com) -UseSsl -Port 587

	$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Incoming Alert from Azure DNS!"
    "themeColor" = '0078D7'
    "title"      = "IOC $server $sub Image"
    "text"       = $evt.Message
}

$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100

$parameters = @{
    "URI"         = 'https://informan.webhook.office.com/webhookb2/52a813f6-b1ad-4a7c-99d7-cbdbd2468956@22507070-ed78-4ce4-a4cc-2393ce92aad6/IncomingWebhook/ccb58ede533c44a08cb3a424e573d12b/dc7d7d4a-15a7-4a35-9185-77871b67a59b'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'
}

Invoke-RestMethod @parameters | Out-Null

	    }



        If(([io.fileinfo]$evt.ParentImage).basename -in $checklist -and ([io.fileinfo]$evt.ParentImage).basename -notin $blacklist) {
                       
        $sub2 = ([io.fileinfo]$evt.Image).name
                       
        #Send-MailMessage -From sandro.conceicao@bravantic.com -To sandro.conceicao@bravantic.com -Subject "IOC $server $sub2"  -Body $evt.Message -SmtpServer smtp.office365.com -Credential (Get-StoredCredential -username sandro.conceicao@bravantic.com) -UseSsl -Port 587


$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Incoming Alert from Azure DNS!"
    "themeColor" = '0078D7'
    "title"      = "IOC $server $sub2 PImage"
    "text"       = $evt.Message
}

$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100

$parameters = @{
    "URI"         = 'https://informan.webhook.office.com/webhookb2/52a813f6-b1ad-4a7c-99d7-cbdbd2468956@22507070-ed78-4ce4-a4cc-2393ce92aad6/IncomingWebhook/ccb58ede533c44a08cb3a424e573d12b/dc7d7d4a-15a7-4a35-9185-77871b67a59b'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'
}

Invoke-RestMethod @parameters | Out-Null

	}
        }
        if ($evt.id -eq 2) {
            $output = @{}
            $output.add("Type", "File Creation Time Changed")
            $output.add("Date", $evt.TimeCreated)
            $output.add("PID", $evt.ProcessId)
            $output.add("Image", $evt.Image)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("CreationUtcTime", $evt.CreationUtcTime)
            $output.add("PreviousCreationUtcTime", $evt.PreviousCreationUtcTime)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 3) {
            $output = @{}
            $output.add("Type", "Network Connection")
            $output.add("Date", $evt.TimeCreated)
            $output.add("Image", $evt.Image)
            $output.add("DestinationIp", $evt.DestinationIp)
            $output.add("DestinationPort", $evt.DestinationPort)
            $output.add("DestinationHost", $evt.DestinationHostname)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log

            #RULES

            If(([io.fileinfo]$evt.Image).basename -in $checklist -and ([io.fileinfo]$evt.DestinationIp).basename -notin $blacklist) {
                       
        $sub2 = ([io.fileinfo]$evt.Image).name
                       
        #Send-MailMessage -From sandro.conceicao@bravantic.com -To sandro.conceicao@bravantic.com -Subject "IOC $server $sub2"  -Body $evt.Message -SmtpServer smtp.office365.com -Credential (Get-StoredCredential -username sandro.conceicao@bravantic.com) -UseSsl -Port 587


$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Incoming Alert from Azure DNS!"
    "themeColor" = '0078D7'
    "title"      = "IOC $server $sub2 PImage"
    "text"       = $evt.Message
}

$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100

$parameters = @{
    "URI"         = 'https://informan.webhook.office.com/webhookb2/52a813f6-b1ad-4a7c-99d7-cbdbd2468956@22507070-ed78-4ce4-a4cc-2393ce92aad6/IncomingWebhook/ccb58ede533c44a08cb3a424e573d12b/dc7d7d4a-15a7-4a35-9185-77871b67a59b'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'
}

Invoke-RestMethod @parameters | Out-Null

	}
        }
        if ($evt.id -eq 5) {
            $output = @{}
            $output.add("Type", "Process Ended")
            $output.add("Date", $evt.TimeCreated)
            $output.add("PID", $evt.ProcessId)
            $output.add("Image", $evt.Image)
            $output.add("CommandLine", $evt.CommandLine)
            $output.add("CurrentDirectory", $evt.CurrentDirectory)
            $output.add("User", $evt.User)
            $output.add("ParentImage", $evt.ParentImage)
            $output.add("ParentCommandLine", $evt.ParentCommandLine)
            $output.add("ParentUser", $evt.ParentUser)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 6) {
            $output = @{}
            $output.add("Type", "Driver Loaded")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 7) {
            $output = @{}
            $output.add("Type", "DLL Loaded By Process")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 8) {
            $output = @{}
            $output.add("Type", "Remote Thread Created")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 9) {
            $output = @{}
            $output.add("Type", "Raw Disk Access")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 10) {
            $output = @{}
            $output.add("Type", "Process Accessed")
            $output.add("Date", $evt.TimeCreated)
	    $output.add("SourceImage", $evt.SourceImage)
	    $output.add("TargetImage", $evt.TargetImage)
	    $output.add("GrantedAccess", $evt.GrantedAccess)
	    $output.add("CallTrace", $evt.CallTrace)
	    $output.add("SourceUser", $evt.SourceUser)
	    $output.add("TargetUser", $evt.TargetUser)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log


#RULES

            If(([io.fileinfo]$evt.SourceImage).basename -in $checklist -and ([io.fileinfo]$evt.SourceImage).basename -notin $blacklist) {
                       
        $sub2 = ([io.fileinfo]$evt.SourceImage).name
                       
        #Send-MailMessage -From sandro.conceicao@bravantic.com -To sandro.conceicao@bravantic.com -Subject "IOC $server $sub2"  -Body $evt.Message -SmtpServer smtp.office365.com -Credential (Get-StoredCredential -username sandro.conceicao@bravantic.com) -UseSsl -Port 587


$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Incoming Alert from Azure DNS!"
    "themeColor" = '0078D7'
    "title"      = "IOC $server $sub2 SImage"
    "text"       = $evt.Message
}

$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100

$parameters = @{
    "URI"         = 'https://informan.webhook.office.com/webhookb2/52a813f6-b1ad-4a7c-99d7-cbdbd2468956@22507070-ed78-4ce4-a4cc-2393ce92aad6/IncomingWebhook/ccb58ede533c44a08cb3a424e573d12b/dc7d7d4a-15a7-4a35-9185-77871b67a59b'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'
}

Invoke-RestMethod @parameters | Out-Null

	}


If(([io.fileinfo]$evt.TargetImage).basename -in $checklist -and ([io.fileinfo]$evt.SourceImage).basename -notin $blacklist) {
                       
        $sub2 = ([io.fileinfo]$evt.TargetImage).name
                       
        #Send-MailMessage -From sandro.conceicao@bravantic.com -To sandro.conceicao@bravantic.com -Subject "IOC $server $sub2"  -Body $evt.Message -SmtpServer smtp.office365.com -Credential (Get-StoredCredential -username sandro.conceicao@bravantic.com) -UseSsl -Port 587


$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Incoming Alert from Azure DNS!"
    "themeColor" = '0078D7'
    "title"      = "IOC $server $sub2 PImage"
    "text"       = $evt.Message
}

$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100

$parameters = @{
    "URI"         = 'https://informan.webhook.office.com/webhookb2/52a813f6-b1ad-4a7c-99d7-cbdbd2468956@22507070-ed78-4ce4-a4cc-2393ce92aad6/IncomingWebhook/ccb58ede533c44a08cb3a424e573d12b/dc7d7d4a-15a7-4a35-9185-77871b67a59b'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'
}

Invoke-RestMethod @parameters | Out-Null

	}


        }
        if ($evt.id -eq 11) {
            $output = @{}
            $output.add("Type", "File Create")
            $output.add("Date", $evt.TimeCreated)
            $output.add("RecordID", $evt.RecordID)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("User", $evt.User)
            $output.add("Process", $evt.Image)
            $output.add("PID", $evt.ProcessID)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 12) {
            $output = @{}
            $output.add("Type", "Registry Added or Deleted")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 13) {
            $output = @{}
            $output.add("Type", "Registry Set")
            $output.add("Date", $evt.TimeCreated)
            $output.add("Image", $evt.Image)
            $output.add("Target Object", $evt.TargetObject)
            $output.add("User", $evt.User)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 14) {
            $output = @{}
            $output.add("Type", "Registry Object Renamed")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 15) {
            $output = @{}
            $output.add("Type", "ADFS Created")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 16) {
            $output = @{}
            $output.add("Type", "Sysmon Configuration Change")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 17) {
            $output = @{}
            $output.add("Type", "Pipe Created")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 18) {
            $output = @{}
            $output.add("Type", "Pipe Connected")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 19) {
            $output = @{}
            $output.add("Type", "WMI Event Filter Activity")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 20) {
            $output = @{}
            $output.add("Type", "WMI Event Consumer Activity")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 21) {
            $output = @{}
            $output.add("Type", "WMI Event Consumer To Filter Activity")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 22) {
            $output = @{}
            $output.add("Type", "DNS Query")
            $output.add("Date", $evt.TimeCreated)
            $output.add("User", $evt.User)
            $output.add("Queryname", $evt.QueryName)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log

            #RULES

            If(([io.fileinfo]$evt.Image).basename -in $checklist -and ([io.fileinfo]$evt.QueryName).basename -notin $blacklist) {
                       
        $sub2 = ([io.fileinfo]$evt.Image).name
                       
        #Send-MailMessage -From sandro.conceicao@bravantic.com -To sandro.conceicao@bravantic.com -Subject "IOC $server $sub2"  -Body $evt.Message -SmtpServer smtp.office365.com -Credential (Get-StoredCredential -username sandro.conceicao@bravantic.com) -UseSsl -Port 587


$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Incoming Alert from Azure DNS!"
    "themeColor" = '0078D7'
    "title"      = "IOC $server $sub2 PImage"
    "text"       = $evt.Message
}

$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100

$parameters = @{
    "URI"         = 'https://informan.webhook.office.com/webhookb2/52a813f6-b1ad-4a7c-99d7-cbdbd2468956@22507070-ed78-4ce4-a4cc-2393ce92aad6/IncomingWebhook/ccb58ede533c44a08cb3a424e573d12b/dc7d7d4a-15a7-4a35-9185-77871b67a59b'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'

}

Invoke-RestMethod @parameters | Out-Null

	}

        }
        if ($evt.id -eq 23) {
            $output = @{}
            $output.add("Type", "File Delete")
            $output.add("Date", $evt.TimeCreated)
            $output.add("RecordID", $evt.RecordID)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("User", $evt.User)
            $output.add("Process", $evt.Image)
            $output.add("PID", $evt.ProcessID)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 24) {
            $output = @{}
            $output.add("Type", "Clipboard Event Monitor")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        if ($evt.id -eq 25) {
            $output = @{}
            $output.add("Type", "Process Tamper")
            $output.add("Date", $evt.TimeCreated)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log

        }
        if ($evt.id -eq 26) {
            $output = @{}
            $output.add("Type", "File Delete Logged")
            $output.add("Date", $evt.TimeCreated)
            $output.add("RecordID", $evt.RecordID)
            $output.add("TargetFilename", $evt.TargetFileName)
            $output.add("User", $evt.User)
            $output.add("Process", $evt.Image)
            $output.add("PID", $evt.ProcessID)
            $outfile = write-alert $output
            write-alert $output
            $outfile = $outfile -join ' | ' | Add-Content C:\Users\Public\Documents\PSSIEM.log
        }
        
     $maxRecordId = $evt.RecordId
    } 

    
}
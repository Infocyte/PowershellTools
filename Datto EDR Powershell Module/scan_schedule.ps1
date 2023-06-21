
function Add-ICScanSchedule {
	[cmdletbinding()]
	param(
		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String]$TargetGroupId,

		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String]$CronExpression,

		[PSObject]$ScanOptions
	)
	$TargetGroup = Get-ICTargetGroup -TargetGroupId $TargetGroupId
	if (-NOT $TargetGroup) {
		Throw "No such target group with id $TargetGroupId"
	}
	$Endpoint = "scheduledJobs"
	Write-Verbose "Creating new schedule for TargetGroup: $($TargetGroup.name) with Cron Express: $CronExpression"
    $body = @{
		name = 'scan-scheduled'
		relatedId = $TargetGroupId
		schedule = $CronExpression
		data = @{
			targetId = $TargetGroupId
		}
	}
	if ($ScanOptions) {
		if ($ScanOptions.EnableProcess -eq $True) {
				$body.data['options'] = $ScanOptions
		} else {
			Throw "ScanScheduleOptions format is invalid -- use New-ICScanScheduleOptions to create an options object"
		}
	}
	Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
}

function Get-ICScanSchedule {
    [cmdletbinding()]
    param(
		[String]$Id,
        [String]$TargetGroupId,
        [HashTable]$where=@{}
    )
    $Endpoint = "ScheduledJobs"
	if ($TargetGroupId) {
		$TargetGroups = Get-ICTargetGroup -TargetGroupId $TargetGroupId
		$ScheduledJobs = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$true | Where-Object { $_.relatedId -eq $TargetGroupId}
	} else {
		$TargetGroups = Get-ICTargetGroup
		$ScheduledJobs = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$true
	}

	$ScheduledJobs | % {
		if ($_.relatedId) {
			 $tgid = $_.relatedId
			 $tg = $TargetGroups | Where-Object { $_.id -eq $tgid }
			 if ($tg) {
				 $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value $tg.name
			 } else {
				 $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value $Null
			 }
		}
	}
	$ScheduledJobs
}

function Remove-ICScanSchedule {
	[cmdletbinding(SupportsShouldProcess, DefaultParameterSetName = 'scheduleId')]
	param(
		[parameter(
			Mandatory,
			ParameterSetName  = 'scheduleId',
			Position = 0,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('scheduleId')]
		[string]$Id,

		[parameter(Mandatory, ParameterSetName  = 'targetGroupId')]
		[ValidateNotNullOrEmpty()]
		[Alias("targetId")]
		$targetGroupId
	)
	PROCESS {
		if (-NOT $Id -AND $_ ) {
			Write-Debug "Taking input from raw pipeline (`$_): $_."
			$Id = $_
		}
		$Schedules = Get-ICScanSchedule
		if ($Id) {
			$schedule = $Schedules | Where-Object { $_.id -eq $Id}
		}
		elseif ($TargetGroupId) {
			$schedule = $Schedules | Where-Object { $_.relatedId -eq $TargetGroupId}
			$ScheduleId	= $schedule.id
		} else {
			throw "Incorrect input!"
		}
		$tgname = $schedule.targetGroup
		if (-NOT $tgname) { throw "TargetGroupId not found!"}
		$Endpoint = "scheduledJobs/$ScheduleId"
	    if ($PSCmdlet.ShouldProcess($Id, "Will remove schedule from $tgname")) {
	    	Write-Warning "Unscheduling collection for Target Group $tgname"
	    	Invoke-ICAPI -Endpoint $Endpoint -method DELETE
	    }
	}
}


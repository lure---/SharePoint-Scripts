[CmdletBinding()]Param();

$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)

## Sample Space
$global:sampleTimeInSeconds = 1;
$global:maxGraphTimeinSeconds = 10;

## Server Topology
$global:wfeServers = @("robdemo-sp");
$global:appServers = @();
$global:sqlServers = @("robdemo-sql");

## Common Counters
$global:commonCounters = @(
    "\Processor(*)\% Processor Time";
);

## WFE servers
$global:wfeServers | % {
    Get-Counter -Counter $global:commonCounters -SampleInterval $global:sampleTimeInSeconds `
        -MaxSamples ($global:maxGraphTimeinSeconds / $global:sampleTimeInSeconds) -ComputerName $_;
}

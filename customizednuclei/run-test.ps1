param(
    [string]$target = "http://waftest.local",
    [string]$output_folder = "stats/crs",
    [int]$workers = 15,
    [ValidateSet("both", "cve", "fuzz")]
    [string]$run_mode = "both",
    [string]$trace_layer = "X-Trace-Layer:*"
)

if ($run_mode -eq "both" -or $run_mode -eq "cve") {
    .\nuclei-waf.exe -template ..\nuclei-templates\http\cves -target $target `
        -output $output_folder\cve2016_2025_output.csv `
        -dump-file $output_folder\cve2016_2025_4xx_5xx.log `
        -dump-status 4**,5** `
        -log-level error `
        -c $workers `
        -mode cve `
        -trace-headers $trace_layer
}

if ($run_mode -eq "both" -or $run_mode -eq "fuzz") {
    .\nuclei-waf.exe -template ..\fuzz-owasp-top10 -target $target `
        -output $output_folder\owasp_top10_output.csv `
        -dump-file $output_folder\owasp_top10_4xx_5xx.log `
        -dump-status 4**,5** `
        -log-level error `
        -c $workers `
        -mode fuzz `
        -trace-headers $trace_layer
}

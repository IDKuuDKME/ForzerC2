# Builds Forzer.exe.
#
# The release build is the one that ships, and the two flags that make it
# release-worthy are here rather than in the README, because a build command
# that has to be typed correctly by hand every time is a build command that
# will eventually be typed wrong and ship an unstripped binary with every
# internal symbol in it:
#
#   -s            strip. Without it the COFF symbol table stays in the file
#                 and carries the source filenames, every static function name
#                 and every global — the whole internal architecture, readable
#                 with `strings` and no execution required.
#   -fno-ident    drop the .comment section, which otherwise names the exact
#                 toolchain build that produced the file.
#
# -DFORZER_DEBUG=1 gives a build that reports everything. It is a debugging
# tool, not a release build: it is not stripped, it prints, and it must not be
# the binary that gets installed.
#
# The debug build is console-subsystem, because a reporting build that cannot
# report is useless: under -mwindows the process has no console and stdout is
# not bound even when it is redirected, so every diagnostic line vanishes.
# Pass -Windowless for a debug build that still looks like production.
#
# The console variant also drops -Wl,--entry,mainCRTStartup. That override
# exists only because a -mwindows binary must be told to enter at main() rather
# than WinMain(); without -mwindows the linker already defaults to
# mainCRTStartup.
#
#   .\build.ps1                      release, stripped, windowless
#   .\build.ps1 -Debug               unstripped, console, full reporting
#   .\build.ps1 -Debug -Windowless   unstripped, windowless, full reporting

param([switch]$Debug, [switch]$Windowless)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# w64devkit installs the driver under a version-suffixed name with short
# forwarder shims alongside it. The shims are what "could not start process"
# means, so the versioned real driver is what gets used here.
function Find-Gcc {
    $candidates = @()
    foreach ($root in @('C:\Tools\w64devkit\bin',
                        (Join-Path $env:LOCALAPPDATA 'w64devkit\bin'),
                        (Join-Path $env:USERPROFILE 'w64devkit\bin'))) {
        if (Test-Path $root) {
            $candidates += Get-ChildItem $root -Filter 'x86_64-w64-mingw32-gcc-*.exe' -ErrorAction SilentlyContinue
        }
    }
    $real = $candidates | Where-Object { $_.Length -gt 1000000 } | Sort-Object Name -Descending | Select-Object -First 1
    if ($real) { return $real.FullName }

    $onPath = Get-Command 'x86_64-w64-mingw32-gcc*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { return $onPath.Source }

    throw "no MinGW driver found; install w64devkit or put x86_64-w64-mingw32-gcc on PATH"
}
$gcc = Find-Gcc

$out    = if ($Debug) { 'Forzer-debug.exe' } else { 'Forzer.exe' }
$common = @(
    '-O2', '-fno-ident',
    '-o', $out,
    'Forzer.c', 'ngcrypt.c',
    '-lws2_32', '-ladvapi32', '-lcrypt32', '-lsecur32', ''
)

# Release is always windowless. A debug build is console unless -Windowless was
# asked for explicitly.
if ((-not $Debug) -or $Windowless) {
    $common += @('-mwindows', '-Wl,--entry,mainCRTStartup')
}

if ($Debug) {
    # -Wno-cast-align: the blob marshalling in ngcrypt.c reads unaligned.
    $flags = $common + @('-DFORZER_DEBUG=1', '-Wno-cast-align')
} else {
    $flags = $common + @('-s', '-Wno-cast-align')
}

Push-Location $here
try {
    & $gcc @flags
    if ($LASTEXITCODE -ne 0) { throw "gcc failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

$built = Get-Item (Join-Path $here $out)
"{0,-18} {1,9:N0} bytes" -f $built.Name, $built.Length

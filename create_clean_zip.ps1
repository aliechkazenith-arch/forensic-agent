# PowerShell Script to create a clean zip archive of the codebase
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$sourceDir = "C:\forensicops-ai"
$zipPath = "C:\forensicops-ai\codebase_clean.zip"

if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

# Directories to exclude
$excludedDirs = @(
    '.git',
    '.env',
    '.venv',
    'venv',
    '__pycache__',
    'node_modules',
    'sample',
    'vault',
    '.pytest_cache',
    'evidence_intake',
    '.antigravity'
)

# File extensions or names to exclude
$excludedFileExts = @(
    '.pyc',
    '.evtx',
    '.blob',
    '.pcap',
    '.etl',
    '.duckdb',
    '.db',
    '.wal',
    '.db-shm',
    '.db-wal'
)

$files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$queue = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
$queue.Enqueue([System.IO.DirectoryInfo]::new($sourceDir))

while ($queue.Count -gt 0) {
    $cur = $queue.Dequeue()
    foreach ($d in $cur.GetDirectories()) {
        if ($excludedDirs -contains $d.Name.ToLower()) {
            continue
        }
        $queue.Enqueue($d)
    }
    foreach ($f in $cur.GetFiles()) {
        if ($f.Name -eq 'codebase_clean.zip' -or $f.Name -eq 'create_clean_zip.ps1') {
            continue
        }
        if ($f.Name.StartsWith('.env') -or $f.Name.EndsWith('.env')) {
            continue
        }
        if ($excludedFileExts -contains $f.Extension.ToLower()) {
            continue
        }
        $files.Add($f)
    }
}

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($sourceDir.Length).TrimStart('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
}
finally {
    $zip.Dispose()
}

$zipItem = Get-Item $zipPath
Write-Host "SUCCESS: Created $($zipItem.FullName) ($([math]::Round($zipItem.Length / 1KB, 2)) KB) with $($files.Count) files."

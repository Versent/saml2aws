Set-StrictMode -Version 'Latest'

$version = $env:GITHUB_REF.Split("/")[2]

echo "Building gossamer3"
go build -o "bin/gossamer3.exe" -ldflags "-X main.Version=${version}" "./cmd/gossamer3"

echo "Copy files into src"
mkdir ./choco/src
Copy-Item "./bin/gossamer3.exe" "./choco/src/gossamer3.exe"
Copy-Item "./LICENSE.md" "./choco/src/LICENSE.md"
Copy-Item "./choco/VERIFICATION.txt" "./choco/src/VERIFICATION.txt"

echo "Running choco pack"
Set-Location choco
choco pack --version "$version" "gossamer3.nuspec"
$hash = Get-FileHash "gossamer3.${version}.nupkg"
"$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "gossamer3.${version}.nupkg.sha256"

echo "Zipping binary"
7z a "gossamer3.zip" "bin\gossamer3.exe"
$hash = Get-FileHash "gossamer3.zip"
"$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "gossamer3.zip.sha256"

echo "Push to choco"
choco apiKey -k $env:CHOCO_API_KEY -source https://push.chocolatey.org/
choco push "./choco/gossamer3.${version}.nupkg"

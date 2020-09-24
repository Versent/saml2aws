Set-StrictMode -Version 'Latest'

$version = ${env:VERSION}

task 'Compile Go libraries...' {
  $ErrorActionPreference = 'Continue'
  go build -o "bin/gossamer3.exe" -ldflags "-X main.Version=${version}" "./cmd/gossamer3"
}

task 'Prepare for choco stuff...' {
  mkdir ./choco/src
  copy-item "./bin/gossamer3.exe" "./choco/src/gossamer3.exe"
  Copy-Item "./LICENSE.md" "./choco/src/LICENSE.md"
  Copy-Item "./choco/VERIFICATION.txt" "./choco/src/VERIFICATION.txt"
}

task 'Pack Choco...' {
  Set-Location choco
  choco pack --version "$version" "gossamer3.nuspec"
  $hash = Get-FileHash "gossamer3.${version}.nupkg"
  "$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "gossamer3.${version}.nupkg.sha256"
}

task 'Zip for GH release...' {
  7z a "gossamer3.zip" "bin\gossamer3.exe"
  $hash = Get-FileHash "gossamer3.zip"
  "$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "gossamer3.zip.sha256"
}

task . 'Compile Go libraries...', 'Prepare for choco stuff...', 'Pack Choco...', 'Zip for GH release...'

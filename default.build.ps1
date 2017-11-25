Set-StrictMode -Version 'Latest'

#$nameOfApp = 'saml2aws'
#$version = '1.3.2'

task 'Compile Go libraries...' {
  $ErrorActionPreference = 'Continue'
  c:\gopath\bin\glide install 2> $null
  $ErrorActionPreference = 'Stop'
  go build -o "bin/${env:appName}.exe" -ldflags "-X main.Version=${env:APPVEYOR_REPO_TAG_NAME}" "./cmd/$env:appName"
}

task 'Prepare for choco stuff...' {
  mkdir ./choco/src
  copy-item "./bin/${env:appName}.exe" "./choco/src/${env:appName}.exe"
  Copy-Item "./LICENSE.md" "./choco/src/LICENSE.md"
  Copy-Item "./choco/VERIFICATION.txt" "./choco/src/VERIFICATION.txt"
}

task 'Pack Choco...' {
  Set-Location choco
  choco pack --version "$env:APPVEYOR_REPO_TAG_NAME" "${env:appName}.nuspec"
  $hash = Get-FileHash "${env:appName}.${env:APPVEYOR_REPO_TAG_NAME}.nupkg"
  "$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "${env:appName}.${env:APPVEYOR_REPO_TAG_NAME}.nupkg.sha256"
}

task 'Zip for GH release...' {
  7z a "${env:appName}.zip" "$env:APPVEYOR_BUILD_FOLDER\bin\${env:appName}.exe"
  $hash = Get-FileHash "${env:appName}.zip"
  "$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "${env:appName}.zip.sha256"
}

task . 'Compile Go libraries...', 'Prepare for choco stuff...', 'Pack Choco...', 'Zip for GH release...'
Set-StrictMode -Version 'Latest'

#$nameOfApp = 'saml2aws'
$version = ${env:APPVEYOR_REPO_TAG_NAME}.Split('v')[1]

task 'Compile Go libraries...' {
  $ErrorActionPreference = 'Continue'
  go install github.com/golang/dep/cmd/dep 2> $null
  c:\gopath\bin\dep ensure 2> $null
  $ErrorActionPreference = 'Stop'
  go build -o "bin/${env:appName}.exe" -ldflags "-X main.Version=${version}" "./cmd/$env:appName"
}

task 'Prepare for choco stuff...' {
  mkdir ./choco/src
  copy-item "./bin/${env:appName}.exe" "./choco/src/${env:appName}.exe"
  Copy-Item "./LICENSE.md" "./choco/src/LICENSE.md"
  Copy-Item "./choco/VERIFICATION.txt" "./choco/src/VERIFICATION.txt"
}

task 'Pack Choco...' {
  Set-Location choco
  choco pack --version "$version" "${env:appName}.nuspec"
  $hash = Get-FileHash "${env:appName}.${version}.nupkg"
  "$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "${env:appName}.${version}.nupkg.sha256"
}

task 'Zip for GH release...' {
  7z a "${env:appName}.zip" "$env:APPVEYOR_BUILD_FOLDER\bin\${env:appName}.exe"
  $hash = Get-FileHash "${env:appName}.zip"
  "$($hash.Hash) $(Split-Path $hash.Path -Leaf)" > "${env:appName}.zip.sha256"
}

task . 'Compile Go libraries...', 'Prepare for choco stuff...', 'Pack Choco...', 'Zip for GH release...'

#!/usr/bin/env sh
candle src/saml2aws.wxs -dSaml2AwsVer=${VERSION} -o "out/"
light -sval "out/saml2aws.wixobj" -o "out/saml2aws_${VERSION}_windows_amd64.msi"

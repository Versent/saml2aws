ARG BASE_IMAGE_ARCH=static-debian11
FROM gcr.io/distroless/$BASE_IMAGE_ARCH
COPY saml2aws /
ENTRYPOINT ["/saml2aws"]
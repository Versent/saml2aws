FROM golang:1.7

RUN wget https://github.com/Masterminds/glide/releases/download/v0.12.3/glide-v0.12.3-linux-amd64.tar.gz && \
    tar xvfz glide-v0.12.3-linux-amd64.tar.gz -C /usr/local/bin --strip-components=1 linux-amd64/glide && \
    rm glide-v0.12.3-linux-amd64.tar.gz
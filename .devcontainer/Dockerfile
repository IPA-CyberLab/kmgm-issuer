ARG VARIANT="1-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/go:0-${VARIANT}

RUN curl -Lo /usr/bin/skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64 && chmod +x /usr/bin/skaffold
RUN curl -L "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/bin/kubectl && chmod +x /usr/bin/kubectl
RUN mkdir /opt/protoc && cd /opt/protoc && \
  curl -L -O https://github.com/protocolbuffers/protobuf/releases/download/v22.0/protoc-22.0-linux-x86_64.zip && \
  unzip *.zip

USER vscode
RUN curl -sS https://webinstall.dev/k9s | bash
RUN mkdir /home/vscode/.kube

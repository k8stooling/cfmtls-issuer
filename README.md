<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# cloudflare-mtls-issuer: cert-manager External Issuer for Cloudflare MTLS

This project implements an external issuer for [cert-manager](https://cert-manager.io/) that leverages Cloudflare's Mutual TLS (mTLS) certificate authority (CA). This issuer allows you to manage and automate Cloudflare mTLS certificate issuance within your Kubernetes clusters using the cert-manager framework.

## Features

*   **Integration with cert-manager:** Seamlessly integrates with cert-manager to handle certificate lifecycle management.
*   **Cloudflare mTLS CA Support:** Issues certificates using your Cloudflare mTLS certificate authority.
*   **Health Checks:** Periodically checks that the CA API is healthy.

## Installation

With Helm

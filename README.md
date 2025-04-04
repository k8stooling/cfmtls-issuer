# <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="cert-manager project logo" style="height: 1em; width: 1em; vertical-align: middle; margin-right: 0.2em;"/> cert-manager.io External Issuer for Cloudflare MTLS

This project implements an external issuer for [cert-manager](https://cert-manager.io/) that leverages Cloudflare's Mutual TLS (mTLS) certificate authority (CA). This issuer allows you to manage and automate Cloudflare mTLS certificate issuance within your Kubernetes clusters using the cert-manager framework.

## Features

*   **Integration with cert-manager:** Seamlessly integrates with cert-manager to handle certificate lifecycle management.
*   **Cloudflare mTLS CA Support:** Issues certificates using your Cloudflare mTLS certificate authority.
*   **Health Checks:** Periodically checks that the CA API is healthy.

## Installation

1. First, you need to install cert-manager.io as per https://cert-manager.io/docs/installation/.

> 📖 kubectl apply: For new users we recommend installing cert-manager using kubectl apply and static manifests.
>
> 📖 helm: You can use helm to install cert-manager and this also allows you to customize the installation if necessary.
> 
> 📖 OperatorHub: If you have an OpenShift cluster, consider installing cert-manager via OperatorHub, which you can do from the OpenShift web console.
> 
> 🚧 cmctl: Try the experimental cmctl x install command to quickly install cert-manager.

As cfmtls-issuer is distributed as a Helm chart, it is pretty straightforward to install cert-manager.io with Helm too. 

2. Deploy the CFMTLS Issuer using Helm:

```sh
helm install cfmtls-issuer oci://ghcr.io/k8stooling/charts/cfmtls-issuer --version 2025.3.5
```

### Configuration via Helm Values

The `values.yaml` contains the configuration for deploying the issuer:

```yaml
# enable automatic approval of certificate requests
approver:
  enabled: true

# Certificates issued are only for 'client auth'
kyverno:
  enabled: true

# the issuer needs to communicate with Cloudflare API and the k8s API
CiliumNetworkPolicy:
  enabled: true
```

## Configuring a ClusterIssuer

Define a `CFMTLSClusterIssuer` to interact with Cloudflare's mTLS API.

Example:

```yaml
apiVersion: cfmtls.cert.manager.io/v1alpha1
kind: CFMTLSClusterIssuer
metadata:
  name: cfmtls
spec:
  authSecretName: cfmtls-auth
```

Ensure that the secret `cfmtls-auth` contains the Cloudflare API key and zone-id:

```sh
kubectl create secret generic cfmtls-auth  --from-literal=cloudflare-zone-id={{ CF_ZONE_ID }} --from-literal=cloudflare-api-key={{ CF_API_KEY }}
```

## Issuing a Certificate

Use the following `Certificate` resource to request a client certificate:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-client-cert
spec:
  secretName: example-client-cert.tls
  issuerRef:
    group: cfmtls.cert.manager.io
    name: cfmtls
    kind: CFMTLSClusterIssuer
  commonName: "client.example.com"
  usages:
    - client auth
  duration: 8760h # 1 year
  renewBefore: 360h # 15 days before expiration
```

## Certificate Approval

By default, certificates may require manual approval.

### Manual Approval

You can use the cert-manager kubectl plugin to manually approve a CertificateSigningRequests (CSR):

```sh
kubectl get csr
kubectl cert-manager approve <csr-name>
```

### Automatic Approval

Or alternatively, you can enable the built-in approver shipped with the issuer in `values.yaml`:

```yaml
approver:
  enabled: true
```

This allows certificates to be automatically approved without manual intervention.

## Troubleshooting

Standard procedures apply
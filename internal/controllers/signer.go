/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes" // 🔹 Added missing import
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	CFMTLSIssuerapi "github.com/krisek/cfmtls-issuer/api/v1alpha1"

	// "encoding/base64"

)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")

	errSignerBuilder = errors.New("failed to build the signer")
	errSignerSign    = errors.New("failed to sign")
)

type CloudflareSigner struct {
	APIKey string
	ZoneID string
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*CFMTLSIssuerapi.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(*x509.Certificate) ([]byte, error)
}

type SignerBuilder func(*CFMTLSIssuerapi.IssuerSpec, map[string][]byte) (Signer, error)

type Issuer struct {
	HealthCheckerBuilder     HealthCheckerBuilder
	SignerBuilder            SignerBuilder
	ClusterResourceNamespace string

	client client.Client
}

func convertDurationToDays(duration string) (int, error) {
    // Parse the duration string (e.g., "8760h0m0s")
    parsedDuration, err := time.ParseDuration(duration)
    if err != nil {
        return 0, err
    }

    // Convert the duration to days (1 day = 24 hours)
    days := int(parsedDuration.Hours() / 24)
    return days, nil
}


// +kubebuilder:rbac:groups=mtls-issuer.cfl,resources=CFMTLSClusterIssuers;CFMTLSIssuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=mtls-issuer.cfl,resources=CFMTLSClusterIssuers/status;CFMTLSIssuers/status,verbs=patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=CFMTLSClusterIssuers.mtls-issuer.cfl/*;CFMTLSIssuers.mtls-issuer.cfl/*

func (s Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.client = mgr.GetClient()

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&CFMTLSIssuerapi.CFMTLSIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&CFMTLSIssuerapi.CFMTLSClusterIssuer{}},

		FieldOwner:       "CFMTLSIssuer.cert-manager.io",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorderFor("CFMTLSIssuer.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}

func (o *Issuer) getIssuerDetails(issuerObject issuerapi.Issuer) (*CFMTLSIssuerapi.IssuerSpec, string, error) {
	switch t := issuerObject.(type) {
	case *CFMTLSIssuerapi.CFMTLSIssuer:
		return &t.Spec, issuerObject.GetNamespace(), nil
	case *CFMTLSIssuerapi.CFMTLSClusterIssuer:
		return &t.Spec, o.ClusterResourceNamespace, nil
	default:
		// A permanent error will cause the Issuer to not retry until the
		// Issuer is updated.
		return nil, "", signer.PermanentError{
			Err: fmt.Errorf("unexpected issuer type: %t", issuerObject),
		}
	}
}

// isClientAuthCert checks if the certificate request includes client authentication usage.
func isClientAuthCert(usages []x509.ExtKeyUsage) bool {
    for _, usage := range usages {
        if usage == x509.ExtKeyUsageClientAuth {
            return true
        }
    }
    return false
}

func (c *CloudflareSigner) Sign(ctx context.Context, csrPEM []byte, validity_days int64) ([]byte, error) {
	logger := log.FromContext(ctx).WithName("Sign")

	requestData := map[string]interface{}{
		"csr": string(csrPEM),
		"validity_days": validity_days,
	}

	// 🔹 Log the request being sent
	requestBody, err := json.MarshalIndent(requestData, "", "  ") // Pretty-print JSON
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	logger.V(2).Info("Full request to Cloudflare API:\n", string(requestBody))

	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/client_certificates", c.ZoneID), bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Cloudflare: %w", err)
	}
	defer resp.Body.Close()

	// 🔹 Log Cloudflare's response
	respBody := new(bytes.Buffer)
	_, _ = respBody.ReadFrom(resp.Body)
	logger.V(2).Info("Cloudflare API Response:", resp.Status, "\n", respBody.String())

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Cloudflare API responded with status: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(respBody).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse Cloudflare response: %w", err)
	}
	
	// Access the certificate from the "result" field
	resultData, ok := result["result"].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid response format: missing 'result' field")
	}
	
	certPEM, ok := resultData["certificate"].(string)
	if !ok {
		return nil, errors.New("invalid certificate response from Cloudflare API")
	}
	
	return []byte(certPEM), nil
}


func (o *Issuer) getSecretData(ctx context.Context, issuerSpec *CFMTLSIssuerapi.IssuerSpec, namespace string) (map[string][]byte, error) {
	secretName := types.NamespacedName{
		Namespace: namespace,
		Name:      issuerSpec.AuthSecretName,
	}

	var secret corev1.Secret
	if err := o.client.Get(ctx, secretName, &secret); err != nil {
		return nil, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
	}

	checker, err := o.HealthCheckerBuilder(issuerSpec, secret.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(); err != nil {
		return nil, fmt.Errorf("%w: %v", errHealthCheckerCheck, err)
	}

	return secret.Data, nil
}

// Check checks that the CA it is available. Certificate requests will not be
// processed until this check passes.
func (o *Issuer) Check(ctx context.Context, issuerObject issuerapi.Issuer) error {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		return err
	}

	_, err = o.getSecretData(ctx, issuerSpec, namespace)
	return err
}

func (o *Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	logger := log.FromContext(ctx).WithName("Sign")

	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	secretData, err := o.getSecretData(ctx, issuerSpec, namespace)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	cfAPIKey := string(secretData["cloudflare-api-key"])
	zoneID := string(secretData["cloudflare-zone-id"])
	if cfAPIKey == "" || zoneID == "" {
		return signer.PEMBundle{}, errors.New("missing Cloudflare API key or Zone ID in secret")
	}

	_, duration, csrPEM, err := cr.GetRequest()
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("failed to get CSR from CertificateRequest: %w", err)
	}

	// Convert duration (which is in hours) to days
	durationInDays := int64(duration.Hours() / 24)

	if len(csrPEM) == 0 {
		return signer.PEMBundle{}, errors.New("CSR in CertificateRequest is empty")
	}

	// 🔹 Print the CSR before sending
	logger.V(2).Info("CSR being sent to Cloudflare:\n", string(csrPEM))
	logger.V(2).Info("Cert duration requested:\n", fmt.Sprintf("%d", durationInDays))

	// 🔹 Pass CSR to CloudflareSigner
	signerObj := &CloudflareSigner{APIKey: cfAPIKey, ZoneID: zoneID}
	signed, err := signerObj.Sign(ctx, csrPEM, durationInDays)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	bundle, err := pki.ParseSingleCertificateChainPEM(signed)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	return signer.PEMBundle(bundle), nil
}

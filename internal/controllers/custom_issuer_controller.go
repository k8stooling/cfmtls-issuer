package controllers

import (
	"context"
	"fmt"

	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CustomIssuerController watches CertificateRequests
type CustomIssuerController struct {
	client client.Client
}

// Reconcile is called when a CertificateRequest is created/updated
func (c *CustomIssuerController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("CustomIssuerController")
	logger.V(2).Info("ME CertificateRequest detected", "name", req.Name, "namespace", req.Namespace)

	// Fetch the CertificateRequest
	cr := &certv1.CertificateRequest{}
	if err := c.client.Get(ctx, req.NamespacedName, cr); err != nil {
		logger.V(2).Error(err, "Failed to get CertificateRequest")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.V(2).Info(fmt.Sprintf("ME CertificateRequest Details: %+v", cr))

	return ctrl.Result{}, nil
}

func (c *CustomIssuerController) SetupWithManager(mgr ctrl.Manager) error {
	c.client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		Named("custom-certificaterequest-controller").
		For(&certv1.CertificateRequest{}). // Removed predicate filtering
		Complete(c)
}



package controllers

import (
	"context"
	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// ApproverController automatically approves CertificateRequests for a custom issuer
type ApproverController struct {
	Client client.Client // change to big Client
}

// Reconcile handles CertificateRequest resources
func (c *ApproverController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("ApproverController")
	logger.V(1).Info("Reconciling CertificateRequest", "name", req.Name, "namespace", req.Namespace)

	// Fetch the CertificateRequest
	cr := &certv1.CertificateRequest{}
	if err := c.Client.Get(ctx, req.NamespacedName, cr); err != nil {
		logger.V(2).Error(err, "Failed to get CertificateRequest")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	} else {
		logger.V(1).Info("Fetched CertificateRequest", "name", req.Name)
	}

	// Check if the CertificateRequest is already approved/denied
	for _, cond := range cr.Status.Conditions {
		if cond.Type == certv1.CertificateRequestConditionApproved || cond.Type == certv1.CertificateRequestConditionDenied {
			logger.V(1).Info("CertificateRequest already processed", "name", req.Name)
			return ctrl.Result{}, nil
		}
	}

	logger.V(1).Info("CertificateRequest will be processed", "name", req.Name)


	// Check if the issuerRef is our custom issuer
	if cr.Spec.IssuerRef.Group == "cfmtls.cert.manager.io" &&
		(cr.Spec.IssuerRef.Kind == "CFMTLSIssuer" || cr.Spec.IssuerRef.Kind == "CFMTLSClusterIssuer") {
		logger.V(1).Info("CertificateRequest is for our custom issuer", "name", req.Name)

		now := metav1.Now()
		// Approve the request
		
		cr.Status.Conditions = append(cr.Status.Conditions, certv1.CertificateRequestCondition{
			Type:               certv1.CertificateRequestConditionApproved,
			Status:             cmmeta.ConditionTrue,
			Reason:             "ApprovedAutomatically",
			Message:            "Automatically approved by CFMTLSIssuer controller",
			LastTransitionTime: &now,
		})

		if err := c.Client.Status().Update(ctx, cr); err != nil { // change client to big Client
			logger.V(2).Error(err, "Failed to update CertificateRequest status")
			return ctrl.Result{}, err
		}

		logger.V(1).Info("Approved CertificateRequest", "name", req.Name)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the manager
func (c *ApproverController) SetupWithManager(mgr ctrl.Manager) error {
	c.Client = mgr.GetClient() // change client to big Client

	return ctrl.NewControllerManagedBy(mgr). //  here you register you controller to manager
		Named("approval-controller").
		For(&certv1.CertificateRequest{}).
		Complete(c)
}

/*
Copyright 2020 IPA CyberLab.

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
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	certmanageriov1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	certmanageriometav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apitypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/pemparser"
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Log    logr.Logger
	ZapLog *zap.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch

// ExtractIssuerNameFromCertificateRequest extracts the kmgm-issuer.coe.ad.jp/Issuer reference from certreq's IssuerRef.
func ExtractIssuerNameFromCertificateRequest(certreq *certmanageriov1.CertificateRequest) (apitypes.NamespacedName, error) {
	issuerRef := certreq.Spec.IssuerRef
	if issuerRef.Group != kmgmissuerv1beta1.GroupVersion.Group {
		return apitypes.NamespacedName{}, fmt.Errorf("certreq issuerRef group %q != %q", issuerRef.Group, kmgmissuerv1beta1.GroupVersion.Group)
	}
	if issuerRef.Kind != "Issuer" {
		return apitypes.NamespacedName{}, fmt.Errorf("certreq issuerRef kind %q != \"Issuer\"", issuerRef.Kind)
	}

	return apitypes.NamespacedName{Namespace: certreq.Namespace, Name: issuerRef.Name}, nil
}

type CertificateRequestConditions struct {
	ReadyCond *certmanageriov1.CertificateRequestCondition
}

func GetCertificateRequestConditions(certreq *certmanageriov1.CertificateRequest) *CertificateRequestConditions {
	var retc CertificateRequestConditions

	conds := certreq.Status.Conditions
	for i := range conds {
		cond := &conds[i]

		switch cond.Type {
		case certmanageriov1.CertificateRequestConditionReady:
			retc.ReadyCond = cond
			break
		}
	}
	return &retc
}

func (c *CertificateRequestConditions) IsReady() bool {
	cond := c.ReadyCond
	return cond != nil && cond.Status == certmanageriometav1.ConditionTrue
}

func (r *CertificateRequestReconciler) ensureCertificateRequestConditions(ctx context.Context, certreq *certmanageriov1.CertificateRequest) (*CertificateRequestConditions, ctrl.Result, error) {
	conds := GetCertificateRequestConditions(certreq)

	condCreated := false
	now := metav1.Now()
	if conds.ReadyCond == nil {
		certreq.Status.Conditions = append(certreq.Status.Conditions, certmanageriov1.CertificateRequestCondition{
			Type:               certmanageriov1.CertificateRequestConditionReady,
			Status:             certmanageriometav1.ConditionFalse,
			LastTransitionTime: &now,
			Reason:             "Bootstrapping",
			Message:            "Bootstrapping msg",
		})
		condCreated = true
	}
	if condCreated {
		if err := r.Status().Update(ctx, certreq); err != nil {
			return nil, ctrl.Result{}, err
		}
		return nil, ctrl.Result{Requeue: true}, nil
	}

	return conds, ctrl.Result{}, nil
}

func (c *CertificateRequestConditions) SetReady() {
	now := metav1.Now()
	c.ReadyCond.Status = certmanageriometav1.ConditionTrue
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "CertificateIssued"
	c.ReadyCond.Message = "Issued the requested certificate successfully"
}

func (c *CertificateRequestConditions) SetErrorState(err error) {
	now := metav1.Now()
	c.ReadyCond.Status = certmanageriometav1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "Failed"
	c.ReadyCond.Message = err.Error()
}

func (r *CertificateRequestReconciler) issueCertificate(ctx context.Context, issuer *kmgmissuerv1beta1.Issuer, certreq *certmanageriov1.CertificateRequest) ([]byte, error) {
	xreq, err := pemparser.ParseCertificateRequest(certreq.Spec.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CertificateRequest PEM: %w", err)
	}

	if err := xreq.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to verify signature of given CSR: %w", err)
	}

	pkixpub, err := x509.MarshalPKIXPublicKey(xreq.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal given public key: %w", err)
	}

	cinfo, err := GetIssuerConnectionInfo(ctx, r, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get kmgm server connection info from issuer: %w", err)
	}
	conn, err := cinfo.Dial(ctx, r.ZapLog)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection to the kmgm server: %w", err)
	}
	defer conn.Close()

	profile := issuer.Spec.Profile
	if profile == "" {
		profile = "default"
	}

	ipaddrstrs := make([]string, 0, len(xreq.IPAddresses))
	for _, ip := range xreq.IPAddresses {
		ipaddrstrs = append(ipaddrstrs, ip.String())
	}

	ku, err := keyusage.FromCSR(xreq)
	if err != nil {
		return nil, fmt.Errorf("failed to extract kmgm KeyUsage from CSR: %w", err)
	}
	// Specify "digital signature" and "key encipherment" by default.
	if ku.KeyUsage == 0 {
		ku.KeyUsage = keyusage.KeyUsageTLSClientServer.KeyUsage
	}
	// cert-manager's default config doesn't specify "server auth" and "client auth".
	// However, they are required in most cases in practice, so we add them here
	// for convenience.
	if len(ku.ExtKeyUsages) == 0 {
		ku.ExtKeyUsages = keyusage.KeyUsageTLSClientServer.ExtKeyUsages
	}

	sc := pb.NewCertificateServiceClient(conn)
	resp, err := sc.IssueCertificate(ctx, &pb.IssueCertificateRequest{
		PublicKey: pkixpub,
		Subject:   dname.FromPkixName(xreq.Subject).ToProtoStruct(),
		Names: &pb.Names{
			Dnsnames: xreq.DNSNames,
			Ipaddrs:  ipaddrstrs,
		},
		NotAfterUnixtime: (time.Now().Add(365 * 24 * time.Hour)).Unix(),
		KeyUsage:         ku.ToProtoStruct(),
		Profile:          profile,
	})
	if err != nil {
		return nil, err
	}

	return pemparser.MarshalCertificateDer(resp.Certificate), nil
}

// Reconcile is our entrypoint for the cert-manager.io/CertificateRequest reconcile loop.
func (r *CertificateRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	l := r.Log.WithValues("certificaterequest", req.NamespacedName)

	var certreq certmanageriov1.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certreq); err != nil {
		if errors.IsNotFound(err) {
			l.Error(nil, "Couldn't find the certificaterequest.")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if len(certreq.Status.Certificate) != 0 {
		l.Info("Ignoring since .Status.Certificate is not empty")
		return ctrl.Result{}, nil
	}

	conds, res, err := r.ensureCertificateRequestConditions(ctx, &certreq)
	if res.Requeue || err != nil {
		return res, err
	}

	issuerName, err := ExtractIssuerNameFromCertificateRequest(&certreq)
	if err != nil {
		return ctrl.Result{}, err
	}

	var issuer kmgmissuerv1beta1.Issuer
	if err := r.Get(ctx, issuerName, &issuer); err != nil {
		if errors.IsNotFound(err) {
			conds.SetErrorState(err)

			if err2 := r.Status().Update(ctx, &certreq); err2 != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return ctrl.Result{}, err
	}
	if !IssuerIsReady(&issuer) {
		conds.SetErrorState(fmt.Errorf("Issuer %v is not yet ready", issuerName))
		if err := r.Status().Update(ctx, &certreq); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	certpem, err := r.issueCertificate(ctx, &issuer, &certreq)
	if err != nil {
		l.Error(err, "issueCertificate")
		conds.SetErrorState(err)
	} else {
		certreq.Status.Certificate = certpem
		conds.SetReady()
	}

	if err := r.Status().Update(ctx, &certreq); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers r to mgr.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanageriov1.CertificateRequest{}).
		Complete(r)
}

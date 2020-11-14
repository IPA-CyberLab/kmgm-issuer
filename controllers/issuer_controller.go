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
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/remote"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
	"github.com/go-logr/logr"
	"github.com/prometheus/common/log"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Log    logr.Logger
	ZapLog *zap.Logger
	Scheme *runtime.Scheme
}

func FindIssuerConditionOfType(issuer *kmgmissuerv1beta1.Issuer, t kmgmissuerv1beta1.IssuerConditionType) *kmgmissuerv1beta1.IssuerCondition {
	conds := issuer.Status.Conditions
	for i := range conds {
		cond := &conds[i]
		if cond.Type == t {
			return cond
		}
	}
	return nil
}

func IssuerIsReady(issuer *kmgmissuerv1beta1.Issuer) bool {
	cond := FindIssuerConditionOfType(issuer, kmgmissuerv1beta1.IssuerConditionReady)
	if cond == nil {
		return false
	}

	return cond.Status == kmgmissuerv1beta1.ConditionTrue
}

func GetIssuerConnectionInfo(ctx context.Context, c client.Client, issuer *kmgmissuerv1beta1.Issuer) (*remote.ConnectionInfo, error) {
	if !IssuerIsReady(issuer) {
		return nil, fmt.Errorf("Issuer %q is not yet ready", issuer.ObjectMeta.Name)
	}

	nname := client.ObjectKey{Namespace: issuer.ObjectMeta.Namespace, Name: issuer.ObjectMeta.Name}

	var secret corev1.Secret
	if err := c.Get(ctx, nname, &secret); err != nil {
		return nil, err
	}

	pkeypem, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("PrivateKey not found in secret %s", secret.ObjectMeta.Name)
	}
	if len(pkeypem) == 0 {
		return nil, fmt.Errorf("PrivateKey PEM empty in secret %s", secret.ObjectMeta.Name)
	}

	certpem, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("Cert not found in secret %s", secret.ObjectMeta.Name)
	}
	if len(certpem) == 0 {
		return nil, fmt.Errorf("Cert PEM empty in secret %s", secret.ObjectMeta.Name)
	}

	cinfo := &remote.ConnectionInfo{
		HostPort:              issuer.Spec.HostPort,
		PinnedPubKey:          issuer.Spec.PinnedPubKey,
		ClientPrivateKeyFile:  storage.InlinePrefix + string(pkeypem),
		ClientCertificateFile: storage.InlinePrefix + string(certpem),
	}
	return cinfo, nil
}

// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=issuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=issuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete

func (r *IssuerReconciler) reconcileSecret(ctx context.Context, req ctrl.Request, issuer *kmgmissuerv1beta1.Issuer) (ctrl.Result, error) {
	l := r.Log.WithValues("issuer", req.NamespacedName)

	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		if !apierrors.IsNotFound(err) {
			l.Error(err, "Failed to get secret")
		}
		l.V(1).Info("secret does not exist")

		secret.Name = issuer.Name
		secret.Namespace = issuer.Namespace
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			corev1.TLSPrivateKeyKey: nil,
			corev1.TLSCertKey:       nil,
		}

		if err := ctrl.SetControllerReference(issuer, &secret, r.Scheme); err != nil {
			log.Error(err, "unable to set secret's controller ref")
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &secret); err != nil {
			log.Error(err, "unable to create secret")
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// FIXME[P2]: check if secret is owned by issuer?

	secretModified := false
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	if pem := secret.Data[corev1.TLSPrivateKeyKey]; len(pem) == 0 {
		priv, err := wcrypto.GenerateKey(rand.Reader, wcrypto.KeySECP256R1, "kmgm-issuer node key", r.ZapLog)
		if err != nil {
			return ctrl.Result{}, err
		}
		bs, err := pemparser.MarshalPrivateKey(priv)
		if err != nil {
			return ctrl.Result{}, err
		}
		secret.Data[corev1.TLSPrivateKeyKey] = bs
		secretModified = true
	}
	if !secretModified {
		if pem := secret.Data[corev1.TLSCertKey]; len(pem) == 0 {
			privpem := secret.Data[corev1.TLSPrivateKeyKey]
			priv, err := pemparser.ParsePrivateKey(privpem)
			if err != nil {
				return ctrl.Result{}, err
			}

			pub, err := wcrypto.ExtractPublicKey(priv)
			if err != nil {
				return ctrl.Result{}, err
			}

			pkixpub, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return ctrl.Result{}, err
			}

			cinfo := &remote.ConnectionInfo{
				HostPort:     issuer.Spec.HostPort,
				PinnedPubKey: issuer.Spec.PinnedPubKey,
				AccessToken:  issuer.Spec.AccessToken,
			}
			conn, err := cinfo.Dial(ctx, r.ZapLog)
			if err != nil {
				return ctrl.Result{}, err
			}
			defer conn.Close()

			sc := pb.NewCertificateServiceClient(conn)
			cn := fmt.Sprintf("kmgm issuer %s/%s", issuer.Namespace, issuer.Name)
			resp, err := sc.IssueCertificate(ctx, &pb.IssueCertificateRequest{
				PublicKey:        pkixpub,
				Subject:          &pb.DistinguishedName{CommonName: cn},
				NotAfterUnixtime: period.FarFuture.NotAfter.Unix(),
				KeyUsage:         keyusage.KeyUsageTLSClient.ToProtoStruct(),
				Profile:          consts.AuthProfileName,
			})
			if err != nil {
				return ctrl.Result{}, err
			}

			certpem := pemparser.MarshalCertificateDer(resp.Certificate)
			secret.Data[corev1.TLSCertKey] = certpem
			secretModified = true
		}
	}
	if secretModified {
		if err := r.Update(ctx, &secret); err != nil {
			log.Error(err, "unable to create secret")
			return ctrl.Result{}, err
		}
		l.V(1).Info("Requeuing after secret gen")
		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{}, nil
}

type issuerConditions struct {
	ReadyCond *kmgmissuerv1beta1.IssuerCondition
}

func (r *IssuerReconciler) ensureIssuerConditions(ctx context.Context, issuer *kmgmissuerv1beta1.Issuer) (*issuerConditions, ctrl.Result, error) {
	var retc issuerConditions

	conds := issuer.Status.Conditions
	for i := range conds {
		cond := &conds[i]

		switch cond.Type {
		case kmgmissuerv1beta1.IssuerConditionReady:
			retc.ReadyCond = cond
			break
		}
	}

	condCreated := false
	now := metav1.Now()
	if retc.ReadyCond == nil {
		issuer.Status.Conditions = append(issuer.Status.Conditions, kmgmissuerv1beta1.IssuerCondition{
			Type:               kmgmissuerv1beta1.IssuerConditionReady,
			Status:             kmgmissuerv1beta1.ConditionFalse,
			LastTransitionTime: &now,
			Reason:             "Bootstrapping",
			Message:            "Bootstrapping msg",
		})
		condCreated = true
	}
	if condCreated {
		if err := r.Status().Update(ctx, issuer); err != nil {
			return nil, ctrl.Result{}, err
		}
		return nil, ctrl.Result{Requeue: true}, nil
	}

	return &retc, ctrl.Result{}, nil
}

func (c *issuerConditions) SetReady() {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionTrue
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "IssuerReady"
	c.ReadyCond.Message = "Bootstrapped issuer successfully"
}

func (c *issuerConditions) SetInProgress() {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "InProgress"
	c.ReadyCond.Message = "Bootstrapping Issuer"
}

func (c *issuerConditions) SetErrorState(reason string, err error) {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = reason
	c.ReadyCond.Message = err.Error()
}

func (r *IssuerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	l := r.Log.WithValues("issuer", req.NamespacedName)

	var issuer kmgmissuerv1beta1.Issuer
	if err := r.Get(ctx, req.NamespacedName, &issuer); err != nil {
		if apierrors.IsNotFound(err) {
			l.Error(nil, "Couldn't find the issuer.")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	conds, res, err := r.ensureIssuerConditions(ctx, &issuer)
	if res.Requeue || err != nil {
		return res, err
	}

	if res, err := r.reconcileSecret(ctx, req, &issuer); err != nil {
		conds.SetErrorState("ClientCertificateFailure", err)

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return ctrl.Result{}, multierr.Append(err, errU)
		}
		return ctrl.Result{}, err
	} else if res.Requeue {
		conds.SetInProgress()

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return ctrl.Result{}, errU
		}
		return res, nil
	}

	conds.SetReady()
	if errU := r.Status().Update(ctx, &issuer); errU != nil {
		return ctrl.Result{}, errU
	}

	return ctrl.Result{}, nil
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmgmissuerv1beta1.Issuer{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

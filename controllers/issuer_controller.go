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
	"go.uber.org/multierr"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
)

const CACertKey = "ca.crt"

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
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

func IssuerHasCliCertIssued(issuer *kmgmissuerv1beta1.Issuer) bool {
	cond := FindIssuerConditionOfType(issuer, kmgmissuerv1beta1.IssuerConditionCliCertIssued)
	if cond == nil {
		return false
	}

	return cond.Status == kmgmissuerv1beta1.ConditionTrue
}

func IssuerIsReady(issuer *kmgmissuerv1beta1.Issuer) bool {
	cond := FindIssuerConditionOfType(issuer, kmgmissuerv1beta1.IssuerConditionReady)
	if cond == nil {
		return false
	}

	return cond.Status == kmgmissuerv1beta1.ConditionTrue
}

func SecretNameFromIssuerName(issuerName types.NamespacedName) types.NamespacedName {
	return types.NamespacedName{
		Namespace: issuerName.Namespace,
		Name:      fmt.Sprintf("%s-kmgm-client-cert", issuerName.Name),
	}
	// TODO[P2]: what if len(Name) > 253
}

func ConfigMapNameFromIssuerName(issuerName types.NamespacedName) types.NamespacedName {
	return types.NamespacedName{
		Namespace: issuerName.Namespace,
		Name:      fmt.Sprintf("%s-ca", issuerName.Name),
	}
	// TODO[P2]: what if len(Name) > 253
}

func GetTokenFromSecret(ctx context.Context, c client.Client, ns string, sel *corev1.SecretKeySelector) (string, error) {
	bootstrapSecretName := types.NamespacedName{
		Namespace: ns,
		Name:      sel.Name,
	}

	var bootstrapSecret corev1.Secret
	if err := c.Get(ctx, bootstrapSecretName, &bootstrapSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return "", fmt.Errorf("kmgm bootstrap Secret %v is not found.", bootstrapSecretName)
		}

		return "", fmt.Errorf("Failed to get kmgm bootstrap Secret %v: %w", bootstrapSecretName, err)
	}
	tokenbs := bootstrapSecret.Data[sel.Key]
	if len(tokenbs) == 0 {
		return "", fmt.Errorf("No data[%q] found inside kmgm bootstrap Secret %v.", sel.Key, bootstrapSecretName)
	}
	bootstrapToken := string(tokenbs)

	return bootstrapToken, nil
}

func GetToken(ctx context.Context, c client.Client, issuer *kmgmissuerv1beta1.Issuer) (string, error) {
	if issuer.Spec.AccessToken != "" {
		return issuer.Spec.AccessToken, nil
	}

	return GetTokenFromSecret(ctx, c, issuer.ObjectMeta.Namespace, issuer.Spec.AccessTokenSecret)
}

func GetIssuerConnectionInfo(ctx context.Context, c client.Client, issuer *kmgmissuerv1beta1.Issuer) (*remote.ConnectionInfo, error) {
	nname := SecretNameFromIssuerName(types.NamespacedName{
		Namespace: issuer.ObjectMeta.Namespace,
		Name:      issuer.ObjectMeta.Name,
	})

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
		ClientPrivateKeyFile:  storage.InlinePrefix + string(pkeypem),
		ClientCertificateFile: storage.InlinePrefix + string(certpem),
	}
	if issuer.Spec.PinnedPubKey == "" {
		if issuer.Status.PubKey == "" {
			cinfo.AllowInsecure = true
		} else {
			cinfo.PinnedPubKey = issuer.Status.PubKey
		}
	} else {
		cinfo.PinnedPubKey = issuer.Spec.PinnedPubKey
	}

	return cinfo, nil
}

func (r *IssuerReconciler) pinPubKey(ctx context.Context, req ctrl.Request, issuer *kmgmissuerv1beta1.Issuer) (ctrl.Result, error) {
	s := r.ZapLog.With(zap.Any("issuer", req.NamespacedName)).Sugar()

	if issuer.Status.PubKey != "" {
		// kmgm server public key already pinned. return.
		return ctrl.Result{}, nil
	}

	if issuer.Spec.PinnedPubKey != "" {
		// Pin kmgm server public key to specified.
		issuer.Status.PubKey = issuer.Spec.PinnedPubKey
	} else {
		token, err := GetToken(ctx, r.Client, issuer)
		if err != nil {
			return RetryAfterDelay, fmt.Errorf("Failed to get token: %w", err)
		}

		cinfo := &remote.ConnectionInfo{
			HostPort:      issuer.Spec.HostPort,
			AllowInsecure: true,
			AccessToken:   token,
		}
		conn, pubkeys, err := cinfo.DialPubKeys(ctx, r.ZapLog)
		if err != nil {
			return RetryAfterDelay, fmt.Errorf("Failed to dial kmgm instance: %w", err)
		}
		defer conn.Close()

		sc := pb.NewVersionServiceClient(conn)
		resp, err := sc.GetVersion(ctx, &pb.GetVersionRequest{})
		if err != nil {
			return RetryAfterDelay, fmt.Errorf("GetVersion gRPC failure: %v", err)
		}

		s.Infof("kmgm server version: %s, commit: %s", resp.Version, resp.Commit)

		// Take first pubkey from `pubkeys`.
		for pubkey := range pubkeys {
			issuer.Status.PubKey = pubkey
			break
		}
	}

	s.Info("Requeuing after pinning kmgm server pubkey")
	return ctrl.Result{Requeue: true}, nil
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete

func (r *IssuerReconciler) reconcileSecret(ctx context.Context, req ctrl.Request, issuer *kmgmissuerv1beta1.Issuer) (ctrl.Result, error) {
	s := r.ZapLog.With(zap.Any("issuer", req.NamespacedName)).Sugar()

	secretName := SecretNameFromIssuerName(req.NamespacedName)

	var secret corev1.Secret
	if err := r.Get(ctx, secretName, &secret); err != nil {
		if !apierrors.IsNotFound(err) {
			return RetryAfterDelay, fmt.Errorf("Failed to get secret: %w", err)
		}

		s.Infof("Secret %v does not exist. Creating.", secretName)

		secret.Name = secretName.Name
		secret.Namespace = secretName.Namespace
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			corev1.TLSPrivateKeyKey: nil,
			corev1.TLSCertKey:       nil,
		}
		secret.Labels = map[string]string{
			"kmgm-issuer.coe.ad.jp/issuer": req.NamespacedName.Name,
		}

		if err := ctrl.SetControllerReference(issuer, &secret, r.Scheme); err != nil {
			return RetryAfterDelay, fmt.Errorf("unable to set secret %v controller ref: %w", secretName, err)
		}
		if err := r.Create(ctx, &secret); err != nil {
			return RetryAfterDelay, fmt.Errorf("Unable to create secret %v: %w", secretName, err)
		}

		s.Infof("Successfully created secret %v. Requeueing.", secretName)
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
			return RetryAfterDelay, fmt.Errorf("Failed to generate private key: %w", err)
		}
		bs, err := pemparser.MarshalPrivateKey(priv)
		if err != nil {
			return RetryAfterDelay, fmt.Errorf("Failed to marshal private key: %w", err)
		}
		secret.Data[corev1.TLSPrivateKeyKey] = bs
		secretModified = true
	}
	if !secretModified {
		if pem := secret.Data[corev1.TLSCertKey]; len(pem) == 0 {
			privpem := secret.Data[corev1.TLSPrivateKeyKey]
			priv, err := pemparser.ParsePrivateKey(privpem)
			if err != nil {
				return RetryAfterDelay, fmt.Errorf("Failed to parse PrivateKey: %w", err)
			}

			pub, err := wcrypto.ExtractPublicKey(priv)
			if err != nil {
				return RetryAfterDelay, fmt.Errorf("Failed to extract public key from the private key: %w", err)
			}

			pkixpub, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return RetryAfterDelay, fmt.Errorf("Failed to marshal public key: %w", err)
			}

			token, err := GetToken(ctx, r.Client, issuer)
			if err != nil {
				return RetryAfterDelay, fmt.Errorf("Failed to get token: %w", err)
			}

			cinfo := &remote.ConnectionInfo{
				HostPort:      issuer.Spec.HostPort,
				PinnedPubKey:  issuer.Spec.PinnedPubKey,
				AllowInsecure: issuer.Spec.PinnedPubKey == "",
				AccessToken:   token,
			}
			conn, err := cinfo.Dial(ctx, r.ZapLog)
			if err != nil {
				return RetryAfterDelay, fmt.Errorf("Failed to dial kmgm instance: %w", err)
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
				return RetryAfterDelay, fmt.Errorf("IssueCertificate gRPC failure: %w", err)
			}

			certpem := pemparser.MarshalCertificateDer(resp.Certificate)
			secret.Data[corev1.TLSCertKey] = certpem
			secretModified = true
		}
	}
	if secretModified {
		if err := r.Update(ctx, &secret); err != nil {
			err = fmt.Errorf("unable to update secret: %w", err)
			s.Error(err)
			return RetryAfterDelay, err
		}
		s.Infof("Successfully updated the secret %v.", secretName)
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete

func (r *IssuerReconciler) reconcileConfigMap(ctx context.Context, req ctrl.Request, issuer *kmgmissuerv1beta1.Issuer) (ctrl.Result, error) {
	s := r.ZapLog.With(zap.Any("issuer", req.NamespacedName)).Named("IssuerReconciler.reconcileConfigMap").Sugar()

	cmName := ConfigMapNameFromIssuerName(req.NamespacedName)

	var cm corev1.ConfigMap
	if err := r.Get(ctx, cmName, &cm); err != nil {
		if !apierrors.IsNotFound(err) {
			return RetryAfterDelay, fmt.Errorf("Failed to get ConfigMap %v: %w", cmName, err)
		}

		cm.Name = cmName.Name
		cm.Namespace = cmName.Namespace

		if err := ctrl.SetControllerReference(issuer, &cm, r.Scheme); err != nil {
			err = fmt.Errorf("unable to set configmap's controller ref: %w", err)
			s.Error(err)
			return RetryAfterDelay, err
		}
		if err := r.Create(ctx, &cm); err != nil {
			err = fmt.Errorf("unable to create configmap: %w", err)
			s.Error(err)
			return RetryAfterDelay, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	cinfo, err := GetIssuerConnectionInfo(ctx, r.Client, issuer)
	if err != nil {
		return RetryAfterDelay, fmt.Errorf("failed to get kmgm server connection info from issuer: %w", err)
	}
	conn, err := cinfo.Dial(ctx, r.ZapLog)
	if err != nil {
		return RetryAfterDelay, fmt.Errorf("failed to establish connection to the kmgm server: %w", err)
	}
	defer conn.Close()

	sc := pb.NewCertificateServiceClient(conn)

	profile := issuer.Spec.Profile
	if profile == "" {
		profile = "default"
	}

	getcertresp, err := sc.GetCertificate(ctx, &pb.GetCertificateRequest{
		Profile:      profile,
		SerialNumber: 0,
	})
	if err != nil {
		return RetryAfterDelay, fmt.Errorf("Failed to GetCertificate(%s, 0): %w", profile, err)
	}
	caPem := pemparser.MarshalCertificateDer(getcertresp.Certificate)
	caPemStr := string(caPem)

	// FIXME[P2]: check if configmap is owned by issuer?

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	if cm.Data[CACertKey] != caPemStr {
		s.Infof("ConfigMap %v %q was not up-to-date. Updating.", cmName, CACertKey)

		cm.Data[CACertKey] = caPemStr
		if err := r.Update(ctx, &cm); err != nil {
			err = fmt.Errorf("unable to update configmap: %w", err)
			s.Error(err)
			return RetryAfterDelay, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

type issuerConditions struct {
	CliCertIssuedCond *kmgmissuerv1beta1.IssuerCondition
	ReadyCond         *kmgmissuerv1beta1.IssuerCondition
}

func (r *IssuerReconciler) ensureIssuerConditions(ctx context.Context, issuer *kmgmissuerv1beta1.Issuer) (*issuerConditions, ctrl.Result, error) {
	s := r.ZapLog.Named("IssuerReconciler.ensureIssuerConditions").
		With(zap.Any("issuer", issuer)).Sugar()

	var retc issuerConditions

	conds := issuer.Status.Conditions
	for i := range conds {
		cond := &conds[i]

		switch cond.Type {
		case kmgmissuerv1beta1.IssuerConditionCliCertIssued:
			retc.CliCertIssuedCond = cond

		case kmgmissuerv1beta1.IssuerConditionReady:
			retc.ReadyCond = cond
		}
	}

	condCreated := false
	now := metav1.Now()
	if retc.CliCertIssuedCond == nil {
		issuer.Status.Conditions = append(issuer.Status.Conditions, kmgmissuerv1beta1.IssuerCondition{
			Type:               kmgmissuerv1beta1.IssuerConditionCliCertIssued,
			Status:             kmgmissuerv1beta1.ConditionFalse,
			LastTransitionTime: &now,
			Reason:             "Bootstrapping",
			Message:            "Bootstrapping msg",
		})
		condCreated = true
	}
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
		s.Info("Instantiated issuer.Status.Conditions. Requeuing.")
		return nil, ctrl.Result{Requeue: true}, nil
	}

	s.Info("Ensured that all conditions are available.")
	return &retc, ctrl.Result{}, nil
}

func (c *issuerConditions) SetCliCertInProgress(msg string) {
	now := metav1.Now()
	c.CliCertIssuedCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.CliCertIssuedCond.LastTransitionTime = &now
	c.CliCertIssuedCond.Reason = "InProgress"
	c.CliCertIssuedCond.Message = msg

	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "InProgress"
	c.ReadyCond.Message = "Client certificate is being bootstrapped"
}

func (c *issuerConditions) SetCliCertError(reason string, err error) {
	now := metav1.Now()
	c.CliCertIssuedCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.CliCertIssuedCond.LastTransitionTime = &now
	c.CliCertIssuedCond.Reason = reason
	c.CliCertIssuedCond.Message = err.Error()

	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "Error"
	c.ReadyCond.Message = "Client certificate bootstrapping failed"
}

func (c *issuerConditions) SetCliCertIssued() {
	if c.CliCertIssuedCond.Status == kmgmissuerv1beta1.ConditionTrue {
		return
	}

	now := metav1.Now()
	c.CliCertIssuedCond.Status = kmgmissuerv1beta1.ConditionTrue
	c.CliCertIssuedCond.LastTransitionTime = &now
	c.CliCertIssuedCond.Reason = "CliCertIssued"
	c.CliCertIssuedCond.Message = "Bootstrapped client certificate successfully"
}

func (c *issuerConditions) SetPostCliCertInProgress(msg string) {
	now := metav1.Now()

	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "InProgress"
	c.ReadyCond.Message = msg
}

func (c *issuerConditions) SetPostCliCertErrorState(reason string, err error) {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = reason
	c.ReadyCond.Message = err.Error()
}

func (c *issuerConditions) SetReady() {
	if c.ReadyCond.Status == kmgmissuerv1beta1.ConditionTrue {
		return
	}

	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionTrue
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "IssuerReady"
	c.ReadyCond.Message = "Bootstrapped issuer completely"
}

// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=issuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=issuers/status,verbs=get;update;patch

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	s := r.ZapLog.With(zap.Any("issuer", req.NamespacedName)).Sugar()

	var issuer kmgmissuerv1beta1.Issuer
	if err := r.Get(ctx, req.NamespacedName, &issuer); err != nil {
		if apierrors.IsNotFound(err) {
			s.Error(err.Error())
			return ctrl.Result{}, err
		}

		err := fmt.Errorf("Failed to `Get` Issuer resource: %v", err)
		s.Error(err.Error())
		return ctrl.Result{}, err
	}

	conds, res, err := r.ensureIssuerConditions(ctx, &issuer)
	if res.Requeue || err != nil {
		return res, err
	}

	if res, err := r.pinPubKey(ctx, req, &issuer); err != nil {
		conds.SetCliCertError("PinPubKeyFailure", err)

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return ctrl.Result{}, multierr.Append(err, errU)
		}

		return RetryAfterDelay, err
	} else if res.Requeue {
		conds.SetCliCertInProgress("Pinned PubKey")

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return RetryAfterDelay, errU
		}
		return res, nil
	}

	if res, err := r.reconcileSecret(ctx, req, &issuer); err != nil {
		conds.SetCliCertError("Error", err)
		err = fmt.Errorf("reconcileSecret failed: %w", err)
		s.Error(err)

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return RetryAfterDelay, multierr.Append(err, errU)
		}
		return res, err
	} else if res.Requeue {
		conds.SetCliCertInProgress("Preparing Secret")

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return RetryAfterDelay, errU
		}
		return res, nil
	}

	conds.SetCliCertIssued()

	if res, err := r.reconcileConfigMap(ctx, req, &issuer); err != nil {
		conds.SetPostCliCertErrorState("CACertConfigMapFailure", err)

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return RetryAfterDelay, multierr.Append(err, errU)
		}
		return res, err
	} else if res.Requeue {
		conds.SetPostCliCertInProgress("Preparing CACertConfigMap")

		if errU := r.Status().Update(ctx, &issuer); errU != nil {
			return RetryAfterDelay, errU
		}
		return res, nil
	}

	conds.SetReady()
	if errU := r.Status().Update(ctx, &issuer); errU != nil {
		return RetryAfterDelay, errU
	}

	return ctrl.Result{}, nil
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmgmissuerv1beta1.Issuer{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

/*
Copyright 2023 IPA CyberLab.

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
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
	"github.com/IPA-CyberLab/kmgm/pb"
)

// KmgmProfileReconciler reconciles a Kmgm object
type KmgmProfileReconciler struct {
	client.Client
	ZapLog *zap.Logger
	Scheme *runtime.Scheme
}

type kmgmProfileCondition struct {
	ReadyCond   *kmgmissuerv1beta1.KmgmProfileCondition
	CASetupCond *kmgmissuerv1beta1.KmgmProfileCondition
}

func (c *kmgmProfileCondition) SetReady() {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionTrue
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "ProfileReady"
	c.ReadyCond.Message = "Kmgm profile is setup successfully."
}

func (c *kmgmProfileCondition) SetInProgress(msg string) {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "InProgress"
	c.ReadyCond.Message = msg
}

func (c *kmgmProfileCondition) SetErrorState(reason string, err error) {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = reason
	c.ReadyCond.Message = err.Error()
}

func (c *kmgmProfileCondition) SetCASetupInProgress() {
	now := metav1.Now()
	c.CASetupCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.CASetupCond.LastTransitionTime = &now
	c.CASetupCond.Reason = "InProgress"
	c.CASetupCond.Message = "CA setup in progress"
}

func (c *kmgmProfileCondition) SetCASetupError(err error) {
	now := metav1.Now()
	c.CASetupCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.CASetupCond.LastTransitionTime = &now
	c.CASetupCond.Reason = "CASetupFailure"
	c.CASetupCond.Message = err.Error()
}

func (c *kmgmProfileCondition) SetCASetupReady() {
	now := metav1.Now()
	c.CASetupCond.Status = kmgmissuerv1beta1.ConditionTrue
	c.CASetupCond.LastTransitionTime = &now
	c.CASetupCond.Reason = "Ready"
	c.CASetupCond.Message = "Kmgm CA is setup successfully."
}

func (r *KmgmProfileReconciler) ensureKmgmProfileConditions(ctx context.Context, p *kmgmissuerv1beta1.KmgmProfile) (*kmgmProfileCondition, ctrl.Result, error) {
	var retc kmgmProfileCondition

	conds := p.Status.Conditions
	for i := range conds {
		cond := &conds[i]

		switch cond.Type {
		case kmgmissuerv1beta1.KmgmProfileConditionReady:
			retc.ReadyCond = cond
		case kmgmissuerv1beta1.KmgmProfileConditionCASetup:
			retc.CASetupCond = cond
		}
	}

	condCreated := false
	now := metav1.Now()
	if retc.ReadyCond == nil {
		p.Status.Conditions = append(p.Status.Conditions, kmgmissuerv1beta1.KmgmProfileCondition{
			Type:               kmgmissuerv1beta1.KmgmProfileConditionReady,
			Status:             kmgmissuerv1beta1.ConditionFalse,
			LastTransitionTime: &now,
			Reason:             "Bootstrapping",
			Message:            "Bootstrapping msg",
		})
		condCreated = true
	}
	if retc.CASetupCond == nil {
		p.Status.Conditions = append(p.Status.Conditions, kmgmissuerv1beta1.KmgmProfileCondition{
			Type:               kmgmissuerv1beta1.KmgmProfileConditionCASetup,
			Status:             kmgmissuerv1beta1.ConditionFalse,
			LastTransitionTime: &now,
			Reason:             "Bootstrapping",
			Message:            "Bootstrapping msg",
		})
		condCreated = true
	}
	if condCreated {
		if err := r.Status().Update(ctx, p); err != nil {
			return nil, ctrl.Result{}, err
		}
		return nil, ctrl.Result{Requeue: true}, nil
	}

	return &retc, ctrl.Result{}, nil
}

func issuerNameFromProfileName(pname types.NamespacedName) types.NamespacedName {
	return pname
}

func makeIssuerSpec(p *kmgmissuerv1beta1.KmgmProfile, kmgm *kmgmissuerv1beta1.Kmgm, bootstrapToken string) kmgmissuerv1beta1.IssuerSpec {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}
	svcName := serviceNameFromKmgmName(nn)

	return kmgmissuerv1beta1.IssuerSpec{
		HostPort:     fmt.Sprintf("%s:34680", svcName.Name),
		PinnedPubKey: "", // empty == pin server pubkey on first conn.
		AccessToken:  bootstrapToken,
		Profile:      p.Name,
	}
}

func (r *KmgmProfileReconciler) reconcileIssuer(ctx context.Context, p *kmgmissuerv1beta1.KmgmProfile, kmgm *kmgmissuerv1beta1.Kmgm) (*kmgmissuerv1beta1.Issuer, ctrl.Result, error) {
	nn := types.NamespacedName{
		Namespace: p.ObjectMeta.Namespace,
		Name:      p.ObjectMeta.Name,
	}
	s := r.ZapLog.With(zap.Any("kmgmProfile", nn)).Sugar()
	s.Info("reconcileIssuer start")
	defer func() {
		s.Info("reconcileIssuer end")
	}()

	bootstrapSecretName := bootstrapSecretNameFromKmgmName(types.NamespacedName{Namespace: kmgm.Namespace, Name: kmgm.Name})
	var bootstrapSecret corev1.Secret
	if err := r.Client.Get(ctx, bootstrapSecretName, &bootstrapSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, RetryAfterDelay, fmt.Errorf("kmgm bootstrap Secret %v is not found.", bootstrapSecretName)
		}

		return nil, RetryAfterDelay, fmt.Errorf("Failed to get kmgm bootstrap Secret %v: %w", bootstrapSecretName, err)
	}
	tokenbs := bootstrapSecret.Data["token"]
	if len(tokenbs) == 0 {
		return nil, RetryAfterDelay, fmt.Errorf("No data[\"token\"] found inside kmgm bootstrap Secret %v.", bootstrapSecretName)
	}
	bootstrapToken := string(tokenbs)

	issuerName := issuerNameFromProfileName(nn)
	var issuer kmgmissuerv1beta1.Issuer
	if err := r.Client.Get(ctx, issuerName, &issuer); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, RetryAfterDelay, fmt.Errorf("Failed to get Issuer: %w", err)
		}

		s.Info("Issuer %v does not exist", issuerName)
		issuer.ObjectMeta = metav1.ObjectMeta{
			Namespace: issuerName.Namespace,
			Name:      issuerName.Name,
			Labels: map[string]string{
				"app.kubernetes.io/component":        "kmgm",
				"app.kubernetes.io/managed-by":       "kmgm-issuer",
				"kmgm-issuer.coe.ad.jp/kmgm":         kmgm.Name,
				"kmgm-issuer.coe.ad.jp/kmgm-profile": p.Name,
			},
			// FIXME: copy labels+annotations (but maybe not those w/ kubectl.kubernetes.io: https://github.com/prometheus-operator/prometheus-operator/blob/16dfbf448ff439907daaa8c58a3b388e1060106f/pkg/alertmanager/statefulset.go#L125)
		}
		issuer.Spec = makeIssuerSpec(p, kmgm, bootstrapToken)

		if err := ctrl.SetControllerReference(p, &issuer, r.Scheme); err != nil {
			err := fmt.Errorf("unable to set the controller ref of issuer %v.", issuerName)
			return nil, RetryAfterDelay, err
		}
		if err := r.Create(ctx, &issuer); err != nil {
			s.Errorf("unable to create issuer: %v", err)
			return nil, RetryAfterDelay, err
		}
		return nil, ctrl.Result{Requeue: true}, nil
	}

	newSpec := makeIssuerSpec(p, kmgm, bootstrapToken)
	diff := cmp.Diff(&newSpec, &issuer.Spec)
	if diff != "" {
		issuer.Spec = newSpec
		if err := r.Update(ctx, &issuer); err != nil {
			return nil, RetryAfterDelay, fmt.Errorf("unable to update Issuer: %w", err)
		}

		return nil, ctrl.Result{Requeue: true}, nil
	}

	// Nothing to do.
	return &issuer, ctrl.Result{}, nil
}

func k8s2pbKeyType(k8s kmgmissuerv1beta1.KmgmKeyType) pb.KeyType {
	switch k8s {
	case kmgmissuerv1beta1.KmgmKeyTypeUnspecified, "":
		return pb.KeyType_KEYTYPE_UNSPECIFIED
	case kmgmissuerv1beta1.KmgmKeyTypeRSA4096:
		return pb.KeyType_KEYTYPE_RSA4096
	case kmgmissuerv1beta1.KmgmKeyTypeSECP256R1:
		return pb.KeyType_KEYTYPE_SECP256R1
	case kmgmissuerv1beta1.KmgmKeyTypeRSA2048:
		return pb.KeyType_KEYTYPE_RSA2048
	default:
		panic(fmt.Sprintf("unknown kmgmissuerv1beta1.KmgmKeyType: %q", k8s))
	}
}

func (r *KmgmProfileReconciler) ensureCA(ctx context.Context, p *kmgmissuerv1beta1.KmgmProfile, kmgm *kmgmissuerv1beta1.Kmgm, issuer *kmgmissuerv1beta1.Issuer) (ctrl.Result, error) {
	nn := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	s := r.ZapLog.With(zap.Any("kmgmProfile", nn)).Sugar()

	if !IssuerIsReady(issuer) {
		return RetryAfterDelay, fmt.Errorf("Issuer %q is not yet ready", issuer.ObjectMeta.Name)
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

	req := &pb.SetupCARequest{
		Profile: p.Name,
		Subject: &pb.DistinguishedName{
			CommonName:         p.Spec.Subject.CommonName,
			Organization:       p.Spec.Subject.Organization,
			OrganizationalUnit: p.Spec.Subject.OrganizationalUnit,
			Country:            p.Spec.Subject.Country,
			Locality:           p.Spec.Subject.Locality,
			Province:           p.Spec.Subject.Province,
			StreetAddress:      p.Spec.Subject.StreetAddress,
			PostalCode:         p.Spec.Subject.PostalCode,
		},
		KeyType:          k8s2pbKeyType(p.Spec.KmgmKeyType),
		NotAfterUnixtime: 0,
	}
	if p.Spec.Validity != nil {
		req.NotAfterUnixtime = time.Now().Add(p.Spec.Validity.Duration).Unix()
	}

	sc := pb.NewCertificateServiceClient(conn)
	if _, err := sc.SetupCA(ctx, req); err != nil {
		st := status.Convert(err)
		if st.Code() == codes.AlreadyExists {
			s.Infof("CA already exists.")
			// FIXME: check cacert if it has the correct subj
			return ctrl.Result{}, nil
		}

		err := fmt.Errorf("SetupCA gRPC has failed: %w", err)
		s.Error(err.Error())
		return RetryAfterDelay, err
	}

	s.Info("SetupCA gRPC was successful.")
	return ctrl.Result{}, nil
}

// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=kmgmprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=kmgmprofiles/status,verbs=get;update;patch

func (r *KmgmProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	s := r.ZapLog.With(zap.Any("kmgmProfile", req.NamespacedName)).Sugar()

	var p kmgmissuerv1beta1.KmgmProfile
	if err := r.Get(ctx, req.NamespacedName, &p); err != nil {
		if apierrors.IsNotFound(err) {
			s.Error(err.Error())
			return ctrl.Result{}, err
		}

		err := fmt.Errorf("Failed to `Get` KmgmProfile resource: %v", err)
		s.Error(err.Error())
		return RetryAfterDelay, err
	}
	conds, res, err := r.ensureKmgmProfileConditions(ctx, &p)
	if res.Requeue || err != nil {
		s.Info("Ensuring profile conditions. err: %v", err)
		return res, err
	}

	kmgmNN := types.NamespacedName{
		Namespace: p.Namespace,
		Name:      p.Spec.KmgmName,
	}

	var kmgm kmgmissuerv1beta1.Kmgm
	if err := r.Get(ctx, kmgmNN, &kmgm); err != nil {
		if apierrors.IsNotFound(err) {
			err := fmt.Errorf("Couldn't find the referenced Kmgm resource %v.", kmgmNN)
			s.Error(err.Error())

			conds.SetErrorState("KmgmNotFound", err)
			if errU := r.Status().Update(ctx, &p); errU != nil {
				return RetryAfterDelay, multierr.Append(err, errU)
			}

			return RetryAfterDelay, err
		}

		err := fmt.Errorf("Failed to get the referenced Kmgm resource %v.", kmgmNN)
		s.Error(err.Error())

		conds.SetErrorState("KmgmAccess", err)
		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, multierr.Append(err, errU)
		}
		return RetryAfterDelay, err
	}

	if !conditionsFromKmgmStatus(&kmgm.Status).IsReady() {
		err := fmt.Errorf("Kmgm %v not yet ready.", kmgmNN)
		conds.SetErrorState("KmgmNotReady", err)
		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, multierr.Append(err, errU)
		}
		return RetryAfterDelay, err
	}

	issuer, res, err := r.reconcileIssuer(ctx, &p, &kmgm)
	if err != nil {
		s.Errorf("reconcileIssuer err: %v", err)
		conds.SetErrorState("IssuerFailure", err)

		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, multierr.Append(err, errU)
		}
		return ctrl.Result{}, err
	} else if res.Requeue {
		s.Infof("reconcileIssuer made progress. requeueing.")

		conds.SetInProgress("PreparingIssuer")
		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, errU
		}

		return res, nil
	}

	if res, err := r.ensureCA(ctx, &p, &kmgm, issuer); err != nil {
		conds.SetCASetupError(err)
		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, multierr.Append(err, errU)
		}
		return RetryAfterDelay, err
	} else if res.Requeue {
		conds.SetCASetupInProgress()
		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, errU
		}
	}

	wasReady := conds.ReadyCond.Status == kmgmissuerv1beta1.ConditionTrue &&
		conds.CASetupCond.Status == kmgmissuerv1beta1.ConditionTrue
	if !wasReady {
		s.Infof("Finished reconciling a KmgmProfile. Updating its status to ready state.")

		conds.SetReady()
		conds.SetCASetupReady()
		if errU := r.Status().Update(ctx, &p); errU != nil {
			return RetryAfterDelay, errU
		}
	}
	return ctrl.Result{}, nil
}

func (r *KmgmProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmgmissuerv1beta1.KmgmProfile{}).
		Owns(&kmgmissuerv1beta1.Issuer{}).
		Complete(r)
}

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
	"crypto/rand"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var RetryAfterDelay = ctrl.Result{RequeueAfter: 3 * time.Second}

func GetKmgmContainerImage(kmgm *kmgmissuerv1beta1.Kmgm) string {
	if kmgm.Spec.Image != "" {
		return kmgm.Spec.Image
	}
	// FIXME
	return "ghcr.io/ipa-cyberlab/kmgm:latest"
}

// KmgmReconciler reconciles a Kmgm object
type KmgmReconciler struct {
	client.Client
	Log    logr.Logger
	ZapLog *zap.Logger
	Scheme *runtime.Scheme
}

type kmgmConditions struct {
	ReadyCond *kmgmissuerv1beta1.KmgmCondition
}

func (c *kmgmConditions) SetReady() {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionTrue
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "KmgmReady"
	c.ReadyCond.Message = "Kmgm bootstrapped successfully."
}

func (c *kmgmConditions) SetInProgress(msg string) {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = "InProgress"
	c.ReadyCond.Message = msg
}

func (c *kmgmConditions) SetErrorState(reason string, err error) {
	now := metav1.Now()
	c.ReadyCond.Status = kmgmissuerv1beta1.ConditionFalse
	c.ReadyCond.LastTransitionTime = &now
	c.ReadyCond.Reason = reason
	c.ReadyCond.Message = err.Error()
}

func (r *KmgmReconciler) ensureKmgmConditions(ctx context.Context, kmgm *kmgmissuerv1beta1.Kmgm) (*kmgmConditions, ctrl.Result, error) {
	var retc kmgmConditions

	conds := kmgm.Status.Conditions
	for i := range conds {
		cond := &conds[i]

		switch cond.Type {
		case kmgmissuerv1beta1.KmgmConditionReady:
			retc.ReadyCond = cond
			break
		}
	}

	condCreated := false
	now := metav1.Now()
	if retc.ReadyCond == nil {
		kmgm.Status.Conditions = append(kmgm.Status.Conditions, kmgmissuerv1beta1.KmgmCondition{
			Type:               kmgmissuerv1beta1.KmgmConditionReady,
			Status:             kmgmissuerv1beta1.ConditionFalse,
			LastTransitionTime: &now,
			Reason:             "Bootstrapping",
			Message:            "Bootstrapping msg",
		})
		condCreated = true
	}
	if condCreated {
		if err := r.Status().Update(ctx, kmgm); err != nil {
			return nil, ctrl.Result{}, err
		}
		return nil, ctrl.Result{Requeue: true}, nil
	}

	return &retc, ctrl.Result{}, nil
}

func bootstrapSecretNameFromKmgmName(kmgmName types.NamespacedName) types.NamespacedName {
	return types.NamespacedName{
		Namespace: kmgmName.Namespace,
		Name:      fmt.Sprintf("%s-kmgm-bootstrap", kmgmName.Name),
	}
	// TODO[P2]: what if len(Name) > 253
}

func statefulSetNameFromKmgmName(kmgmName types.NamespacedName) types.NamespacedName {
	return types.NamespacedName{
		Namespace: kmgmName.Namespace,
		Name:      fmt.Sprintf("%s-kmgm-instance", kmgmName.Name),
	}
	// TODO[P2]: what if len(Name) > 253
}

func serviceNameFromKmgmName(kmgmName types.NamespacedName) types.NamespacedName {
	return statefulSetNameFromKmgmName(kmgmName)
}

func issuerNameFromKmgmName(kmgmName types.NamespacedName) types.NamespacedName {
	return kmgmName
}

func (r *KmgmReconciler) createBootstrapSecret(ctx context.Context, kmgm *kmgmissuerv1beta1.Kmgm) error {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}
	l := r.Log.WithValues("KmgmReconciler.createBootstrapSecret", nn)

	sn := bootstrapSecretNameFromKmgmName(nn)

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sn.Name,
			Namespace: sn.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/component":  "kmgm",
				"app.kubernetes.io/managed-by": "kmgm-issuer",
				"kmgm-issuer.coe.ad.jp/kmgm":   kmgm.Name,
			},
		},
	}

	if err := ctrl.SetControllerReference(kmgm, s, r.Scheme); err != nil {
		l.Error(err, "Failed to set controller reference of bootstrap secret.")
		return err
	}
	if err := r.Create(ctx, s); err != nil {
		l.Error(err, "Failed to create bootstrap Secret resource.")
		return err
	}

	l.Info("Successfully created bootstrap Secret resource.", "NamespacedName", sn)
	return nil
}

func (r *KmgmReconciler) reconcileSecret(ctx context.Context, kmgm *kmgmissuerv1beta1.Kmgm) (ctrl.Result, string, error) {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}

	l := r.Log.WithValues("kmgm", nn)
	l.Info("reconcileSecret start")
	defer func() {
		l.Info("reconcileSecret end")
	}()

	secretName := bootstrapSecretNameFromKmgmName(nn)
	var bootstrapSecret corev1.Secret
	if err := r.Client.Get(ctx, secretName, &bootstrapSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return RetryAfterDelay, "", fmt.Errorf("Failed to get Secret: %w", err)
		}

		if err := r.createBootstrapSecret(ctx, kmgm); err != nil {
			l.Error(err, "unable to create secret")
		}
		return ctrl.Result{Requeue: true}, "", nil
	}

	// ensure data.token
	tokenbs := bootstrapSecret.Data["token"]

	var bootstrapToken string
	if len(tokenbs) > 0 {
		bootstrapToken = string(tokenbs)
	}
	if bootstrapToken == "" {
		if token, err := wcrypto.GenBase64Token(rand.Reader, r.ZapLog); err != nil {
			return RetryAfterDelay, "", fmt.Errorf("Failed to generate bootstrap token: %w", err)
		} else {
			if bootstrapSecret.StringData == nil {
				bootstrapSecret.StringData = make(map[string]string)
			}
			bootstrapSecret.StringData["token"] = token

			if err := r.Client.Update(ctx, &bootstrapSecret); err != nil {
				return RetryAfterDelay, "", fmt.Errorf("Failed to update Secret: %w", err)
			}
			return ctrl.Result{Requeue: true}, "", nil
		}
	}

	return ctrl.Result{}, bootstrapToken, nil
}

var persistentVolumeFilesystem = corev1.PersistentVolumeFilesystem

func podMatchLabels(kmgm *kmgmissuerv1beta1.Kmgm) map[string]string {
	return map[string]string{
		"app.kubernetes.io/component": "kmgm",
		"kmgm-issuer.coe.ad.jp/kmgm":  kmgm.Name,
	}
}

func makeStatefulSetSpec(kmgm *kmgmissuerv1beta1.Kmgm) appsv1.StatefulSetSpec {
	sn := bootstrapSecretNameFromKmgmName(types.NamespacedName{Namespace: kmgm.Namespace, Name: kmgm.Name})

	matchLabels := podMatchLabels(kmgm)
	nonMatchLabels := map[string]string{
		"app.kubernetes.io/managed-by": "kmgm-issuer",
	}
	ls := labels.Merge(matchLabels, nonMatchLabels)

	return appsv1.StatefulSetSpec{
		Replicas: ptrint32(1),
		Selector: &metav1.LabelSelector{
			MatchLabels: matchLabels,
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: ls,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "kmgm",
					Image: GetKmgmContainerImage(kmgm),
					Args: []string{
						"serve",
						"--bootstrap-token-file",
						"/etc/kmgm-token/token",
						"--expose-metrics",
					},
					Ports: []corev1.ContainerPort{{
						Name:          "http",
						ContainerPort: 34680,
						Protocol:      corev1.ProtocolTCP,
					}},
					Env: []corev1.EnvVar{{
						Name:  "KMGMDIR",
						Value: "/var/lib/kmgm",
					}},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "profile-vol",
							MountPath: "/var/lib/kmgm",
						},
						{
							Name:      "token-vol",
							MountPath: "/etc/kmgm-token",
						},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/healthz",
								Port:   intstr.IntOrString{Type: intstr.String, StrVal: "http"},
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
					ImagePullPolicy: corev1.PullIfNotPresent,
				}},
				Volumes: []corev1.Volume{{
					Name: "token-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: sn.Name,
						},
					},
				}},
				TerminationGracePeriodSeconds: ptrint64(30),
			},
		},
		VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PersistentVolumeClaim",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "profile-vol",
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						"storage": *resource.NewQuantity(104857600, resource.BinarySI),
					},
				},
				VolumeMode: &persistentVolumeFilesystem,
			}},
		},
		UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
			Type:          appsv1.RollingUpdateStatefulSetStrategyType,
			RollingUpdate: &appsv1.RollingUpdateStatefulSetStrategy{},
		},
	}
}

// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;delete

func (r *KmgmReconciler) reconcileStatefulSet(ctx context.Context, kmgm *kmgmissuerv1beta1.Kmgm) (ctrl.Result, error) {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}

	l := r.Log.WithValues("kmgm", nn)
	l.Info("reconcileStatefulSet start")
	defer func() {
		l.Info("reconcileStatefulSet end")
	}()

	ssetName := statefulSetNameFromKmgmName(nn)
	var sset appsv1.StatefulSet
	if err := r.Client.Get(ctx, ssetName, &sset); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, fmt.Errorf("Failed to get StatefulSet: %w", err)
		}

		l.V(1).Info("statefulset does not exist")
		sset.ObjectMeta = metav1.ObjectMeta{
			Namespace: ssetName.Namespace,
			Name:      ssetName.Name,
			Labels: map[string]string{
				"app.kubernetes.io/component":  "kmgm",
				"app.kubernetes.io/managed-by": "kmgm-issuer",
				"kmgm-issuer.coe.ad.jp/kmgm":   kmgm.Name,
			},
			// FIXME: copy labels+annotations (but maybe not those w/ kubectl.kubernetes.io: https://github.com/prometheus-operator/prometheus-operator/blob/16dfbf448ff439907daaa8c58a3b388e1060106f/pkg/alertmanager/statefulset.go#L125)
		}
		sset.Spec = makeStatefulSetSpec(kmgm)

		if err := ctrl.SetControllerReference(kmgm, &sset, r.Scheme); err != nil {
			l.Error(err, "unable to set statefulset's controller ref")
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &sset); err != nil {
			l.Error(err, "unable to create statefulset")
		}
		return ctrl.Result{Requeue: true}, nil
	}

	newSpec := makeStatefulSetSpec(kmgm)
	diff := cmp.Diff(&newSpec, &sset.Spec)
	if diff == "" {
		// Nothing to do.
		return ctrl.Result{}, nil
	}

	sset.Spec = newSpec
	if err := r.Update(ctx, &sset); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update statefulset: %w", err)
	}

	return ctrl.Result{}, nil
}

func makeServiceSpec(kmgm *kmgmissuerv1beta1.Kmgm) corev1.ServiceSpec {
	return corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:       "http",
				Protocol:   corev1.ProtocolTCP,
				Port:       34680,
				TargetPort: intstr.IntOrString{Type: intstr.String, StrVal: "http"},
			},
		},
		Selector: podMatchLabels(kmgm),
	}
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete

func (r *KmgmReconciler) reconcileService(ctx context.Context, kmgm *kmgmissuerv1beta1.Kmgm) (ctrl.Result, error) {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}
	l := r.Log.WithValues("kmgm", nn)
	l.Info("reconcileService start")
	defer func() {
		l.Info("reconcileService end")
	}()

	svcName := serviceNameFromKmgmName(nn)
	var svc corev1.Service
	if err := r.Client.Get(ctx, svcName, &svc); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, fmt.Errorf("Failed to get Service: %w", err)
		}

		l.V(1).Info("Service does not exist")
		svc.ObjectMeta = metav1.ObjectMeta{
			Namespace: svcName.Namespace,
			Name:      svcName.Name,
			Labels: map[string]string{
				"app.kubernetes.io/component":  "kmgm",
				"app.kubernetes.io/managed-by": "kmgm-issuer",
				"kmgm-issuer.coe.ad.jp/kmgm":   kmgm.Name,
			},
			// FIXME: copy labels+annotations (but maybe not those w/ kubectl.kubernetes.io: https://github.com/prometheus-operator/prometheus-operator/blob/16dfbf448ff439907daaa8c58a3b388e1060106f/pkg/alertmanager/statefulset.go#L125)
		}
		svc.Spec = makeServiceSpec(kmgm)

		if err := ctrl.SetControllerReference(kmgm, &svc, r.Scheme); err != nil {
			l.Error(err, "unable to set service's controller ref")
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &svc); err != nil {
			l.Error(err, "unable to create Service")
		}
		return ctrl.Result{Requeue: true}, nil
	}

	newSpec := makeServiceSpec(kmgm)
	// Only compare the fields that controller cares about.
	if cmp.Diff(newSpec.Ports, &svc.Spec.Ports) == "" &&
		cmp.Diff(newSpec.Selector, &svc.Spec.Selector) == "" {
		// Nothing to do.
		return ctrl.Result{}, nil
	}

	svc.Spec.Ports = newSpec.Ports
	svc.Spec.Selector = newSpec.Selector
	if err := r.Update(ctx, &svc); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update Service: %w", err)
	}

	return ctrl.Result{}, nil
}

func makeIssuerSpec(kmgm *kmgmissuerv1beta1.Kmgm, bootstrapToken string) kmgmissuerv1beta1.IssuerSpec {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}
	svcName := serviceNameFromKmgmName(nn)

	return kmgmissuerv1beta1.IssuerSpec{
		HostPort:     fmt.Sprintf("%s:34680", svcName.Name),
		PinnedPubKey: "", // empty == pin server pubkey on first conn.
		AccessToken:  bootstrapToken,
	}
}

func (r *KmgmReconciler) reconcileIssuer(ctx context.Context, kmgm *kmgmissuerv1beta1.Kmgm, bootstrapToken string) (ctrl.Result, error) {
	nn := types.NamespacedName{
		Namespace: kmgm.ObjectMeta.Namespace,
		Name:      kmgm.ObjectMeta.Name,
	}
	l := r.Log.WithValues("kmgm", nn)
	l.Info("reconcileIssuer start")
	defer func() {
		l.Info("reconcileIssuer end")
	}()

	issuerName := issuerNameFromKmgmName(nn)
	var issuer kmgmissuerv1beta1.Issuer
	if err := r.Client.Get(ctx, issuerName, &issuer); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, fmt.Errorf("Failed to get Issuer: %w", err)
		}

		l.V(1).Info("Issuer does not exist")
		issuer.ObjectMeta = metav1.ObjectMeta{
			Namespace: issuerName.Namespace,
			Name:      issuerName.Name,
			Labels: map[string]string{
				"app.kubernetes.io/component":  "kmgm",
				"app.kubernetes.io/managed-by": "kmgm-issuer",
				"kmgm-issuer.coe.ad.jp/kmgm":   kmgm.Name,
			},
			// FIXME: copy labels+annotations (but maybe not those w/ kubectl.kubernetes.io: https://github.com/prometheus-operator/prometheus-operator/blob/16dfbf448ff439907daaa8c58a3b388e1060106f/pkg/alertmanager/statefulset.go#L125)
		}
		issuer.Spec = makeIssuerSpec(kmgm, bootstrapToken)

		if err := ctrl.SetControllerReference(kmgm, &issuer, r.Scheme); err != nil {
			l.Error(err, "unable to set issuer's controller ref")
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &issuer); err != nil {
			l.Error(err, "unable to create issuer")
		}
		return ctrl.Result{Requeue: true}, nil
	}

	newSpec := makeIssuerSpec(kmgm, bootstrapToken)
	diff := cmp.Diff(&newSpec, &issuer.Spec)
	if diff == "" {
		// Nothing to do.
		return ctrl.Result{}, nil
	}

	issuer.Spec = newSpec
	if err := r.Update(ctx, &issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update Issuer: %w", err)
	}

	return ctrl.Result{}, nil
}

// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=kmgms,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=kmgms/status,verbs=get;update;patch

func (r *KmgmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var kmgm kmgmissuerv1beta1.Kmgm
	if err := r.Get(ctx, req.NamespacedName, &kmgm); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("Couldn't find the kmgm resource.")
		}

		return ctrl.Result{}, err
	}

	conds, res, err := r.ensureKmgmConditions(ctx, &kmgm)
	if res.Requeue || err != nil {
		return res, err
	}
	_ = conds

	res, bootstrapToken, err := r.reconcileSecret(ctx, &kmgm)
	if err != nil {
		conds.SetErrorState("Secret failure", err)

		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, multierr.Append(err, errU)
		}
		return ctrl.Result{}, err
	} else if res.Requeue {
		conds.SetInProgress("Preparing Secret")
		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, errU
		}

		return res, nil
	}

	if res, err := r.reconcileStatefulSet(ctx, &kmgm); err != nil {
		conds.SetErrorState("StatefulSet failure", err)

		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, multierr.Append(err, errU)
		}
		return ctrl.Result{}, err
	} else if res.Requeue {
		conds.SetInProgress("Preparing StatefulSet")
		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, errU
		}

		return res, nil
	}

	if res, err := r.reconcileService(ctx, &kmgm); err != nil {
		conds.SetErrorState("Service failure", err)

		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, multierr.Append(err, errU)
		}
		return ctrl.Result{}, err
	} else if res.Requeue {
		conds.SetInProgress("Preparing Service")
		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, errU
		}

		return res, nil
	}

	if res, err := r.reconcileIssuer(ctx, &kmgm, bootstrapToken); err != nil {
		conds.SetErrorState("Issuer failure", err)

		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, multierr.Append(err, errU)
		}
		return ctrl.Result{}, err
	} else if res.Requeue {
		conds.SetInProgress("Preparing Issuer")
		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, errU
		}

		return res, nil
	}

	wasReady := conds.ReadyCond.Status == kmgmissuerv1beta1.ConditionTrue
	if !wasReady {
		conds.SetReady()
		if errU := r.Status().Update(ctx, &kmgm); errU != nil {
			return ctrl.Result{}, errU
		}
	}
	return ctrl.Result{}, nil
}

func (r *KmgmReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmgmissuerv1beta1.Kmgm{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Service{}).
		Owns(&kmgmissuerv1beta1.Issuer{}).
		Complete(r)
}

func ptrint32(p int32) *int32 {
	return &p
}

func ptrint64(p int64) *int64 {
	return &p
}

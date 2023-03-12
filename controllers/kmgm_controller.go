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

	"github.com/go-logr/logr"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
)

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

// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=kmgms,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kmgm-issuer.coe.ad.jp,resources=kmgms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;delete

func (r *KmgmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := r.Log.WithValues("issuer", req.NamespacedName)

	var kmgm kmgmissuerv1beta1.Kmgm
	if err := r.Get(ctx, req.NamespacedName, &kmgm); err != nil {
		if apierrors.IsNotFound(err) {
			l.Error(nil, "Couldn't find the kmgm resource.")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	conds, res, err := r.ensureKmgmConditions(ctx, &kmgm)
	if res.Requeue || err != nil {
		return res, err
	}
	_ = conds

	return ctrl.Result{}, nil
}

func (r *KmgmReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmgmissuerv1beta1.Kmgm{}).
		Owns(&appsv1.StatefulSet{}).
		Complete(r)
}

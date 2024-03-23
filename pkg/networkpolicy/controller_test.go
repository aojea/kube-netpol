package networkpolicy

import (
	"fmt"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

var alwaysReady = func() bool { return true }

type fakeReconciler struct {
	Policy Policy
}

func (f fakeReconciler) Reconcile(name string, policy Policy) error {
	if !reflect.DeepEqual(policy, f.Policy) {
		return fmt.Errorf("policies doesn't match %+v %+v", policy, f.Policy)
	}
	return nil
}

type networkpolicyController struct {
	*Controller
	networkpolicyStore cache.Store
	namespaceStore     cache.Store
	podStore           cache.Store
}

func newController() *networkpolicyController {
	client := fake.NewSimpleClientset()
	informersFactory := informers.NewSharedInformerFactory(client, 0)
	controller := NewController(client,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		fakeReconciler{},
	)
	controller.networkpoliciesSynced = alwaysReady
	controller.namespacesSynced = alwaysReady
	controller.podsSynced = alwaysReady
	return &networkpolicyController{
		controller,
		informersFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		informersFactory.Core().V1().Namespaces().Informer().GetStore(),
		informersFactory.Core().V1().Pods().Informer().GetStore(),
	}
}

func TestSyncNetworkPolicy(t *testing.T) {
	npName := "test"
	ns := "test-ns"
	tests := []struct {
		name           string
		networkpolicy  *networkingv1.NetworkPolicy
		namespace      *v1.Namespace
		pod            *v1.Pod
		expectedPolicy *Policy
	}{
		{
			name: "Default deny all traffic",
			networkpolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default-deny-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{},
					Egress:      []networkingv1.NetworkPolicyEgressRule{},
				},
			},
			namespace:      &v1.Namespace{},
			pod:            &v1.Pod{},
			expectedPolicy: &Policy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController()
			// Add objects to the Store

			controller.networkpolicyStore.Add(tt.networkpolicy)
			controller.namespaceStore.Add(tt.namespace)
			controller.podStore.Add(tt.pod)

			err := controller.syncNetworkPolicy(ns + "/" + npName)
			if err != nil {
				t.Errorf("syncServices error: %v", err)
			}

		})
	}
}

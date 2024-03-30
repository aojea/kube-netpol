package networkpolicy

import (
	"fmt"
	"net"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

type netpolTweak func(networkPolicy *networkingv1.NetworkPolicy)

func makeNetworkPolicyCustom(name, ns string, tweaks ...netpolTweak) *networkingv1.NetworkPolicy {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       networkingv1.NetworkPolicySpec{},
	}
	for _, fn := range tweaks {
		fn(networkPolicy)
	}
	return networkPolicy
}

func makePort(proto *v1.Protocol, port intstr.IntOrString, endPort int32) networkingv1.NetworkPolicyPort {
	r := networkingv1.NetworkPolicyPort{
		Protocol: proto,
		Port:     nil,
	}
	if port != intstr.FromInt32(0) && port != intstr.FromString("") && port != intstr.FromString("0") {
		r.Port = &port
	}
	if endPort != 0 {
		r.EndPort = ptr.To[int32](endPort)
	}
	return r
}

func makeNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/metadata.name": name,
				"a":                           "b",
			},
		},
	}
}
func makePod(name, ns string, ip string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"a": "b",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "write-pod",
					Command: []string{"/bin/sh"},
					Ports: []v1.ContainerPort{{
						Name:          "http",
						ContainerPort: 80,
						Protocol:      v1.ProtocolTCP,
					}},
				},
			},
		},
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{IP: ip},
			},
		},
	}

	return pod

}

var alwaysReady = func() bool { return true }

type networkpolicyController struct {
	*Controller
	networkpolicyStore cache.Store
	namespaceStore     cache.Store
	podStore           cache.Store
}

func newController() *networkpolicyController {
	ipt, err := iptables.New()
	if err != nil {
		panic(fmt.Sprintf("New failed: %v", err))
	}
	client := fake.NewSimpleClientset()
	informersFactory := informers.NewSharedInformerFactory(client, 0)
	controller := NewController(client,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		ipt,
		100,
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

func TestSyncPacket(t *testing.T) {
	logs.GlogSetter("4")
	state := klog.CaptureState()
	t.Cleanup(state.Restore)

	protocolTCP := v1.ProtocolTCP

	podA := makePod("a", "foo", "192.168.1.11")
	podB := makePod("b", "bar", "192.168.2.22")

	npDefaultDenyIngress := makeNetworkPolicyCustom("default-deny-ingress", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
		})

	npDefaultDenyEgress := makeNetworkPolicyCustom("default-deny-ingress", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
		})

	npAllowAllIngress := makeNetworkPolicyCustom("default-allow-ingress", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
			networkPolicy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
		})

	npMultiPortEgress := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				Ports: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromInt32(30000), 65537)},
				To:    []networkingv1.NetworkPolicyPeer{},
			}}
		})

	npMultiPortEgressIPBlock := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/16"},
				}},
			}}
		})

	npMultiPortEgressPodSelector := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	npMultiPortEgressNsSelector := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	npMultiPortEgressPodNsSelector := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	tests := []struct {
		name          string
		networkpolicy []*networkingv1.NetworkPolicy
		namespace     []*v1.Namespace
		pod           []*v1.Pod
		p             packet
		expect        bool
	}{
		{
			name:          "no network policy",
			networkpolicy: []*networkingv1.NetworkPolicy{},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "deny ingress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "deny egress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.2.22"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.1.11"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "deny egress on reply does not have effect",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "allow all override deny ingress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress, npAllowAllIngress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport deny egress port",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow egress port",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 30080,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressIPBlock},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress port selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress port selector fail",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow egress ns selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress ns selector fail",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow egress ns and pod selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress ns and pod selector fail",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB},
			p: packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController()
			// Add objects to the Store

			for _, n := range tt.networkpolicy {
				controller.networkpolicyStore.Add(n)
			}
			for _, n := range tt.namespace {
				controller.namespaceStore.Add(n)
			}
			for _, p := range tt.pod {
				controller.podStore.Add(p)
			}

			ok := controller.acceptPacket(tt.p)
			if ok != tt.expect {
				t.Errorf("expected %v got  %v", ok, tt.expect)
			}

		})
	}
}

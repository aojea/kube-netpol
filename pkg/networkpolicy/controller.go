package networkpolicy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"github.com/prometheus/client_golang/prometheus"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
)

// Network policies are hard to implement efficiently and in large clusters this is translated to performance and
// scalability problems.
// Most of the existing implementation use the same approach of processing the APIs and transforming them in the
// corresponding dataplane implementation, commonly this may be iptables, nftables, ebpf or ovs.
// This takes a different approach, it uses the NFQUEUE functionality implemented in netfilter to process
// the first packet of each connection in userspace and emit a veredict. The advantages is that the dataplane
// implementation does not need to represent all the complex logic.
// There are also some performance improvements that can be applied, as to restrict the packets that are sent to
// userspace to the ones that have network policies only.
// This effectively means that network policies are applied ONLY at the time the connection is initatied
// by whatever the conntrack kernel understand by NEW connection.
// https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
// https://netfilter.org/projects/libnetfilter_queue/doxygen/html/

const (
	controllerName = "kube-netpol"
	podIPIndex     = "podIPKeyIndex"
)

var (
	histogramVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "packet_process_time",
		Help: "Time it has taken to process each packet (microseconds)",
	}, []string{"protocol", "family"})

	packetCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_count",
		Help: "Number of packets",
	}, []string{"protocol", "family"})
)

var registerMetricsOnce sync.Once

// RegisterMetrics registers kube-proxy metrics.
func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.Register(histogramVec)
		prometheus.Register(packetCounterVec)
	})
}

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	ipt *iptables.IPTables,
	nfqueueID int,
) *Controller {
	klog.V(4).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	c := &Controller{
		client:    client,
		ipt:       ipt,
		nfqueueID: nfqueueID,
	}

	// TODO handle dual stack
	podInformer.Informer().AddIndexers(cache.Indexers{
		podIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return []string{}, nil
			}
			// TODO check this later or it can block some traffic
			// unrelated to the Pod
			if pod.Spec.HostNetwork {
				return []string{}, nil
			}
			result := []string{}
			for _, ip := range pod.Status.PodIPs {
				result = append(result, string(ip.IP))
			}
			return result, nil
		},
	})

	podIndexer := podInformer.Informer().GetIndexer()
	// Theoretically only one IP can be active at a time
	c.getPodAssignedToIP = func(podIP string) *v1.Pod {
		objs, err := podIndexer.ByIndex(podIPIndex, podIP)
		if err != nil {
			return nil
		}
		if len(objs) == 0 {
			return nil
		}
		// if there are multiple pods use the one that is running
		for _, obj := range objs {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				continue
			}
			if pod.Status.Phase == v1.PodRunning {
				return pod
			}
		}
		// if no pod is running pick the first one
		// TODO: check multiple phases
		return objs[0].(*v1.Pod)
	}

	c.podLister = podInformer.Lister()
	c.podsSynced = podInformer.Informer().HasSynced
	c.namespaceLister = namespaceInformer.Lister()
	c.namespacesSynced = namespaceInformer.Informer().HasSynced
	c.networkpolicyLister = networkpolicyInformer.Lister()
	c.networkpoliciesSynced = networkpolicyInformer.Informer().HasSynced

	c.eventBroadcaster = broadcaster
	c.eventRecorder = recorder

	return c
}

// Controller manages selector-based networkpolicy endpoints.
type Controller struct {
	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	// informers for network policies, namespaces and pods
	networkpolicyLister   networkinglisters.NetworkPolicyLister
	networkpoliciesSynced cache.InformerSynced
	namespaceLister       corelisters.NamespaceLister
	namespacesSynced      cache.InformerSynced
	podLister             corelisters.PodLister
	podsSynced            cache.InformerSynced

	// function to get the Pod given an IP
	// if an error or not found it returns nil
	getPodAssignedToIP func(podIP string) *v1.Pod
	// install the necessary iptables rules
	ipt       *iptables.IPTables
	nfq       *nfqueue.Nfqueue
	nfqueueID int
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()

	klog.Infof("Starting controller %s", controllerName)
	defer klog.Infof("Shutting down controller %s", controllerName)

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), c.networkpoliciesSynced, c.namespacesSynced, c.podsSynced) {
		return fmt.Errorf("error syncing cache")
	}

	// add metrics
	registerMetrics()

	// Start the workers after the repair loop to avoid races
	klog.Info("Syncing iptables rules")
	c.syncIptablesRules()
	defer c.cleanIptablesRules()
	go wait.Until(c.syncIptablesRules, 60*time.Second, ctx.Done())

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(c.nfqueueID),
		MaxPacketLen: 128, // only interested in the headers
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket, // headers
		// WriteTimeout: 500 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		klog.Infof("could not open nfqueue socket: %v", err)
		return err
	}
	defer nf.Close()

	c.nfq = nf

	// Parse the packet and check if should be accepted
	fn := func(a nfqueue.Attribute) int {
		startTime := time.Now()
		klog.Infof("Processing sync for packet %d", *a.PacketID)

		packet, err := parsePacket(*a.Payload)
		if err != nil {
			klog.Infof("Can not process packet %d accepting it: %v", *a.PacketID, err)
			c.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}

		verdict := c.acceptPacket(packet)
		if verdict {
			c.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		} else {
			c.nfq.SetVerdict(*a.PacketID, nfqueue.NfDrop)
		}
		histogramVec.WithLabelValues(string(packet.proto), string(c.ipt.Proto())).Observe(float64(time.Since(startTime).Microseconds()))
		packetCounterVec.WithLabelValues(string(packet.proto), string(c.ipt.Proto())).Inc()
		klog.V(0).Infof("Finished syncing packet %d took %v result %v", *a.PacketID, time.Since(startTime), verdict)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		klog.Infof("Could not receive message: %v\n", err)
		return 0
	})
	if err != nil {
		klog.Infof("could not open nfqueue socket: %v", err)
		return err
	}

	<-ctx.Done()

	return nil
}

// syncIptablesRules adds the necessary rules to process the first connection packets in userspace
// and check if network policies must apply.
// --queue-bypass is on other NFQUEUE option by Florian Westphal.
// It change the behavior of a iptables rules when no userspace software is connected to the queue.
// Instead of dropping packets, the packet are authorized if no software is listening to the queue.
func (c *Controller) syncIptablesRules() {
	if err := c.ipt.InsertUnique("filter", "FORWARD", 1, "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-num", strconv.Itoa(c.nfqueueID)); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}

	if err := c.ipt.InsertUnique("filter", "OUTPUT", 1, "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-num", strconv.Itoa(c.nfqueueID)); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}
}

func (c *Controller) cleanIptablesRules() {
	if err := c.ipt.Delete("filter", "FORWARD", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-num", strconv.Itoa(c.nfqueueID)); err != nil {
		klog.Infof("error deleting iptables rule %v", err)
	}

	if err := c.ipt.Delete("filter", "OUTPUT", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-num", strconv.Itoa(c.nfqueueID)); err != nil {
		klog.Infof("error deleting iptables rule %v", err)
	}
}

func (c *Controller) getNetworkPoliciesForPod(pod *v1.Pod) []*networkingv1.NetworkPolicy {
	if pod == nil {
		return nil
	}
	// Get all the network policies that affect this pod
	networkPolices, err := c.networkpolicyLister.NetworkPolicies(pod.Namespace).List(labels.Everything())
	if err != nil {
		return nil
	}
	return networkPolices
}

func (c *Controller) acceptPacket(p packet) bool {
	srcIP := p.srcIP
	srcPod := c.getPodAssignedToIP(srcIP.String())
	srcPort := p.srcPort
	dstIP := p.dstIP
	dstPod := c.getPodAssignedToIP(dstIP.String())
	dstPort := p.dstPort
	protocol := p.proto
	srcPodNetworkPolices := c.getNetworkPoliciesForPod(srcPod)
	dstPodNetworkPolices := c.getNetworkPoliciesForPod(dstPod)

	msg := fmt.Sprintf("checking packet %s\n", p.String())
	if srcPod != nil {
		msg = msg + fmt.Sprintf("\tSrcPod (%s/%s) %d network policies\n", srcPod.Name, srcPod.Namespace, len(srcPodNetworkPolices))
	}
	if dstPod != nil {
		msg = msg + fmt.Sprintf("\tDstPod (%s/%s) %d network policies\n", dstPod.Name, dstPod.Namespace, len(dstPodNetworkPolices))
	}
	klog.V(2).Infof("%s", msg)

	// For a connection from a source pod to a destination pod to be allowed,
	// both the egress policy on the source pod and the ingress policy on the
	// destination pod need to allow the connection.
	// If either side does not allow the connection, it will not happen.

	// This is the first packet originated from srcPod so we need to check:
	// 1. srcPod egress is accepted
	// 2. dstPod ingress is accepted
	return c.validator(srcPodNetworkPolices, networkingv1.PolicyTypeEgress, srcPod, srcIP, srcPort, dstPod, dstIP, dstPort, protocol) &&
		c.validator(dstPodNetworkPolices, networkingv1.PolicyTypeIngress, dstPod, dstIP, dstPort, srcPod, srcIP, srcPort, protocol)
}

// validator obtains a verdict for network policies that applies to a src Pod in the direction
// passed as parameter
func (c *Controller) validator(
	networkPolicies []*networkingv1.NetworkPolicy, networkPolictType networkingv1.PolicyType,
	srcPod *v1.Pod, srcIP net.IP, srcPort int, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {
	verdict := true
	for _, netpol := range networkPolicies {
		// podSelector selects the pods to which this NetworkPolicy object applies.
		// The array of ingress rules is applied to any pods selected by this field.
		// Multiple network policies can select the same set of pods. In this case,
		// the ingress rules for each are combined additively.
		// This field is NOT optional and follows standard label selector semantics.
		// An empty podSelector matches all pods in this namespace.
		podSelector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
		if err != nil {
			klog.Infof("error parsing PodSelector: %v", err)
			continue
		}
		// networkPolicy does not selects the pod try the next network policy
		if !podSelector.Matches(labels.Set(srcPod.Labels)) {
			klog.V(2).Infof("Pod %s/%s does not match NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
			continue
		}

		for _, policyType := range netpol.Spec.PolicyTypes {
			if policyType != networkPolictType {
				continue
			}

			if policyType == networkingv1.PolicyTypeEgress {
				// egress is a list of egress rules to be applied to the selected pods. Outgoing traffic
				// is allowed if there are no NetworkPolicies selecting the pod (and cluster policy
				// otherwise allows the traffic), OR if the traffic matches at least one egress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
				// solely to ensure that the pods it selects are isolated by default).
				if netpol.Spec.Egress == nil {
					klog.V(2).Infof("Pod %s/%s has limited all egress traffic by NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
					verdict = false
					continue
				}

				if len(netpol.Spec.Egress) == 0 {
					klog.V(2).Infof("Pod %s/%s has allowed all egress traffic by NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
					return true
				}

				for _, rule := range netpol.Spec.Egress {
					if len(rule.Ports) != 0 {
						ok := c.validatePorts(rule.Ports, dstPod, dstPort, proto)
						if !ok {
							klog.V(2).Infof("Pod %s/%s is not allowed to connect to port %d by NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, dstPort, netpol.Name, netpol.Namespace)
							verdict = false
							continue
						}
					}
					// to is a list of destinations for outgoing traffic of pods selected for this rule.
					// Items in this list are combined using a logical OR operation. If this field is
					// empty or missing, this rule matches all destinations (traffic not restricted by
					// destination). If this field is present and contains at least one item, this rule
					// allows traffic only if the traffic matches at least one item in the to list.
					if len(rule.To) == 0 {
						klog.V(2).Infof("Pod %s/%s is allowed to connect to any destination on NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
						return true
					}
					for _, peer := range rule.To {
						// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
						// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
						// that should not be included within this rule.
						if peer.IPBlock != nil {
							if c.validateIPBlocks(peer.IPBlock, dstIP) {
								klog.V(2).Infof("Pod %s/%s is allowed to connect to %s on NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, dstIP, netpol.Name, netpol.Namespace)
								return true
							} else {
								verdict = false
								continue
							}
						}

						if dstPod == nil {
							continue
						}
						// podSelector is a label selector which selects pods. This field follows standard label
						// selector semantics; if present but empty, it selects all pods.
						//
						// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
						// Otherwise it selects the pods matching podSelector in the policy's own namespace.
						if peer.PodSelector != nil {
							podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
							if err != nil {
								klog.Infof("Accepting packet, error: %v", err)
								return true
							}
							// networkPolicy does not selects the pod
							// try the next network policy
							if !podSelector.Matches(labels.Set(dstPod.Labels)) {
								klog.V(2).Infof("Pod %s/%s is not allowed to connect from %s/%s on NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
								verdict = false
								continue
							}
							if peer.NamespaceSelector == nil && dstPod.Namespace == netpol.Namespace {
								klog.V(2).Infof("Pod %s/%s is allowed to connect from %s/%s on NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
								return true
							}
						}
						// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
						// standard label selector semantics; if present but empty, it selects all namespaces.
						//
						// If podSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the namespaces selected by namespaceSelector.
						// Otherwise it selects all pods in the namespaces selected by namespaceSelector.
						if peer.NamespaceSelector != nil {
							nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
							if err != nil {
								klog.Infof("Accepting packet, error: %v", err)
								return true
							}

							namespaces, err := c.namespaceLister.List(nsSelector)
							if err != nil {
								klog.Infof("Accepting packet, error: %v", err)
								return true
							}
							for _, ns := range namespaces {
								if dstPod.Namespace == ns.Name {
									klog.V(2).Infof("Pod %s/%s is allowed to connect from %s/%s on NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
									return true
								}
							}
							klog.V(2).Infof("Pod %s/%s is not allowed to connect from %s/%s on NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
							verdict = false
							continue
						}
					}
				}
			}

			if policyType == networkingv1.PolicyTypeIngress {
				// ingress is a list of ingress rules to be applied to the selected pods.
				// Traffic is allowed to a pod if there are no NetworkPolicies selecting the pod
				// (and cluster policy otherwise allows the traffic), OR if the traffic source is
				// the pod's local node, OR if the traffic matches at least one ingress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy does not allow any traffic (and serves
				// solely to ensure that the pods it selects are isolated by default)
				if netpol.Spec.Ingress == nil {
					klog.V(2).Infof("Pod %s/%s has limited all ingress traffic by NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, netpol.Name, netpol.Namespace)
					verdict = false
					continue
				}

				if len(netpol.Spec.Ingress) == 0 {
					klog.V(2).Infof("Pod %s/%s has allowed all ingress traffic by NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, netpol.Name, netpol.Namespace)
					return true
				}

				for _, rule := range netpol.Spec.Ingress {
					if len(rule.Ports) != 0 {
						ok := c.validatePorts(rule.Ports, srcPod, srcPort, proto)
						if !ok {
							klog.V(2).Infof("Pod %s/%s is not allowed to connect from port %d by NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, srcPort, netpol.Name, netpol.Namespace)
							verdict = false
							continue
						}
					}
					// to is a list of destinations for outgoing traffic of pods selected for this rule.
					// Items in this list are combined using a logical OR operation. If this field is
					// empty or missing, this rule matches all destinations (traffic not restricted by
					// destination). If this field is present and contains at least one item, this rule
					// allows traffic only if the traffic matches at least one item in the to list.
					if len(rule.From) == 0 {
						klog.V(2).Infof("Pod %s/%s is allowed to connect from any destination on NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, netpol.Name, netpol.Namespace)
						return true
					}
					for _, peer := range rule.From {
						// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
						// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
						// that should not be included within this rule.
						if peer.IPBlock != nil {
							if c.validateIPBlocks(peer.IPBlock, srcIP) {
								klog.V(2).Infof("Pod %s/%s is allowed to connect from %s on NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, srcIP, netpol.Name, netpol.Namespace)
								return true
							} else {
								verdict = false
								continue
							}
						}
						if dstPod == nil {
							continue
						}
						// podSelector is a label selector which selects pods. This field follows standard label
						// selector semantics; if present but empty, it selects all pods.
						//
						// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
						// Otherwise it selects the pods matching podSelector in the policy's own namespace.
						if peer.PodSelector != nil {
							podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
							if err != nil {
								klog.Infof("Accepting packet, error: %v", err)
								return true
							}
							// networkPolicy does not selects the pod
							// try the next network policy
							if !podSelector.Matches(labels.Set(srcPod.Labels)) {
								verdict = false
								continue
							}
							if peer.NamespaceSelector == nil && srcPod.Namespace == netpol.Namespace {
								return true
							}
						}
						// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
						// standard label selector semantics; if present but empty, it selects all namespaces.
						//
						// If podSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the namespaces selected by namespaceSelector.
						// Otherwise it selects all pods in the namespaces selected by namespaceSelector.
						if peer.NamespaceSelector != nil {
							nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
							if err != nil {
								klog.Infof("Accepting packet, error: %v", err)
								return true
							}

							namespaces, err := c.namespaceLister.List(nsSelector)
							if err != nil {
								klog.Infof("Accepting packet, error: %v", err)
								return true
							}
							for _, ns := range namespaces {
								if srcPod.Namespace == ns.Name {
									return true
								}
							}
							verdict = false
						}
						continue
					}
				}
			}
		}
	}
	return verdict
}

func (c *Controller) validateIPBlocks(ipBlock *networkingv1.IPBlock, ip net.IP) bool {
	if ipBlock == nil {
		return true
	}

	_, cidr, err := net.ParseCIDR(ipBlock.CIDR)
	if err != nil { // this has been validated by the API
		return true
	}

	if !cidr.Contains(ip) {
		return false
	}

	for _, except := range ipBlock.Except {
		_, cidr, err := net.ParseCIDR(except)
		if err != nil { // this has been validated by the API
			return true
		}
		if cidr.Contains(ip) {
			return false
		}
	}
	// it matched the cidr and didn't match the exceptions
	return true
}

func (c *Controller) validatePorts(networkPolicyPorts []networkingv1.NetworkPolicyPort, pod *v1.Pod, port int, protocol v1.Protocol) bool {
	// ports is a list of ports,  each item in this list is combined using a logical OR.
	// If this field is empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	if len(networkPolicyPorts) == 0 {
		return true
	}

	for _, policyPort := range networkPolicyPorts {
		if protocol != *policyPort.Protocol {
			continue
		}
		// matches all ports
		if policyPort.Port == nil {
			return true
		}
		if port == policyPort.Port.IntValue() {
			return true
		}
		if pod != nil && policyPort.Port.StrVal != "" {
			for _, container := range pod.Spec.Containers {
				for _, p := range container.Ports {
					if p.Name == policyPort.Port.StrVal &&
						p.ContainerPort == int32(port) &&
						p.Protocol == protocol {
						return true
					}
				}
			}
		}
		// endPort indicates that the range of ports from port to endPort if set, inclusive,
		// should be allowed by the policy. This field cannot be defined if the port field
		// is not defined or if the port field is defined as a named (string) port.
		// The endPort must be equal or greater than port.
		if policyPort.EndPort == nil {
			continue
		}
		if port > policyPort.Port.IntValue() && int32(port) <= *policyPort.EndPort {
			return true
		}
	}
	return false
}

type packet struct {
	srcIP   net.IP
	dstIP   net.IP
	proto   v1.Protocol
	srcPort int
	dstPort int
	payload []byte
}

func (p packet) String() string {
	return fmt.Sprintf("%s:%d %s:%d %s :: %s", p.srcIP.String(), p.srcPort, p.dstIP.String(), p.dstPort, p.proto, string(p.payload))
}

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
// https://en.wikipedia.org/wiki/IPv6_packet
// https://github.com/golang/net/blob/master/ipv4/header.go
func parsePacket(b []byte) (packet, error) {
	t := packet{}
	if b == nil {
		return t, fmt.Errorf("empty payload")
	}
	version := int(b[0] >> 4)
	// initialize variables
	hdrlen := -1
	protocol := -1
	switch version {
	case 4:
		hdrlen = int(b[0]&0x0f) << 2
		if len(b) < hdrlen+4 {
			return t, fmt.Errorf("payload to short, received %d expected at least %d", len(b), hdrlen+4)
		}
		t.srcIP = net.IPv4(b[12], b[13], b[14], b[15])
		t.dstIP = net.IPv4(b[16], b[17], b[18], b[19])
		protocol = int(b[9])
	case 6:
		hdrlen = 40
		if len(b) < hdrlen+4 {
			return t, fmt.Errorf("payload to short, received %d expected at least %d", len(b), hdrlen+4)
		}
		t.srcIP = make(net.IP, net.IPv6len)
		copy(t.srcIP, b[8:24])
		t.dstIP = make(net.IP, net.IPv6len)
		copy(t.dstIP, b[24:40])
		// NextHeader (not extension headers supported)
		protocol = int(b[6])
	default:
		return t, fmt.Errorf("unknown versions %d", version)
	}

	switch protocol {
	case 6:
		t.proto = v1.ProtocolTCP
	case 17:
		t.proto = v1.ProtocolUDP
	case 132:
		t.proto = v1.ProtocolSCTP
	default:
		return t, fmt.Errorf("unknown protocol %d", protocol)
	}
	// TCP, UDP and SCTP srcPort and dstPort are the first 4 bytes after the IP header
	t.srcPort = int(binary.BigEndian.Uint16(b[hdrlen : hdrlen+2]))
	t.dstPort = int(binary.BigEndian.Uint16(b[hdrlen+2 : hdrlen+4]))
	// Obtain the offset of the payload
	// TODO allow to filter by the payload
	dataOffset := int(b[hdrlen+12] >> 4)
	if len(b) >= hdrlen+dataOffset {
		t.payload = b[hdrlen+dataOffset:]
	}
	return t, nil
}

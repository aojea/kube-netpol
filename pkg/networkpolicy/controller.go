package networkpolicy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-iptables/iptables"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

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
	"k8s.io/client-go/util/workqueue"
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
	// maxRetries is the number of times a object will be retried before it is dropped out of the queue.
	// With the current rate-limiter in use (5ms*2^(maxRetries-1)) the following numbers represent the
	// sequence of delays between successive queuings of an object.
	//
	// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1.3s
	maxRetries = 9

	controllerName = "kube-netpol"
)

var (
	histogramVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "packet_process_time",
		Help: "Time it has taken to process each packet",
	}, []string{"protocol"})

	packetCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_count",
		Help: "Number of packets",
	}, []string{"protocol"})
)

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	ipt *iptables.IPTables,
) *Controller {
	klog.V(4).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	c := &Controller{
		client:           client,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), controllerName),
		workerLoopPeriod: time.Second,
		ipt:              ipt,
	}

	// TODO handle dual stack
	podInformer.Informer().AddIndexers(cache.Indexers{
		"podIPKeyIndex": func(obj interface{}) ([]string, error) {
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
				result = append(result, ip.String())
			}
			return result, nil
		},
	})

	podIndexer := podInformer.Informer().GetIndexer()
	c.getPodsAssignedToIP = func(podIP string) ([]*v1.Pod, error) {
		objs, err := podIndexer.ByIndex("podIPKeyIndex", podIP)
		if err != nil {
			return nil, err
		}
		pods := make([]*v1.Pod, 0, len(objs))
		for _, obj := range objs {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				continue
			}
			pods = append(pods, pod)
		}
		return pods, nil
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
	getPodsAssignedToIP func(podIP string) ([]*v1.Pod, error)
	// install the necessary iptables rules
	ipt *iptables.IPTables
	nfq *nfqueue.Nfqueue
	// rate limited queue
	queue workqueue.RateLimitingInterface

	// workerLoopPeriod is the time between worker runs. The workers process the queue of networkpolicy and pod changes.
	workerLoopPeriod time.Duration
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting controller %s", controllerName)
	defer klog.Infof("Shutting down controller %s", controllerName)

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), c.networkpoliciesSynced, c.namespacesSynced, c.podsSynced) {
		return fmt.Errorf("error syncing cache")
	}

	// add metrics
	prometheus.MustRegister(histogramVec)
	prometheus.MustRegister(packetCounterVec)

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":9080", nil)

	// Start the workers after the repair loop to avoid races
	klog.Info("Syncing iptables rules")
	c.syncIptablesRules()
	defer c.cleanIptablesRules()
	go wait.Until(c.syncIptablesRules, 60*time.Second, ctx.Done())

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      100,
		MaxPacketLen: 128, // only interested in the headers
		MaxQueueLen:  255,
		Copymode:     nfqueue.NfQnlCopyPacket, // headers
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		klog.Infof("could not open nfqueue socket:", err)
		return err
	}
	defer nf.Close()

	c.nfq = nf

	fn := func(a nfqueue.Attribute) int {
		klog.V(4).Infof("Processing packet %+v", (*a.Payload)[:40])
		c.queue.Add(a)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, fn)
	if err != nil {
		klog.Infof("could not open nfqueue socket:", err)
		return err
	}

	klog.Info("Starting workers")
	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, ctx.Done())
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
	if err := c.ipt.InsertUnique("filter", "FORWARD", 1, "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-num", "100"); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}

	if err := c.ipt.InsertUnique("filter", "OUTPUT", 1, "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-num", "100"); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}
}

func (c *Controller) cleanIptablesRules() {
	if err := c.ipt.Delete("filter", "FORWARD", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "0:5", "--queue-cpu-fanout"); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}

	if err := c.ipt.Delete("filter", "OUTPUT", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "0:5", "--queue-cpu-fanout"); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same networkpolicy
// at the same time.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	eKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(eKey)
	a := eKey.(nfqueue.Attribute)
	err := c.syncPacket(a)
	c.handleErr(err, a)
	return true
}

func (c *Controller) handleErr(err error, key nfqueue.Attribute) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < maxRetries {
		klog.V(2).InfoS("Error syncing networkpolicy, retrying", "packet", key, "err", err)
		c.queue.AddRateLimited(key)
		return
	}

	klog.Warningf("Dropping packet %v out of the queue: %v", key, err)
	// TODO drop or accept???
	c.nfq.SetVerdict(*key.PacketID, nfqueue.NfDrop)
	c.queue.Forget(key)
	utilruntime.HandleError(err)
}

func (c *Controller) syncPacket(key nfqueue.Attribute) error {
	startTime := time.Now()
	klog.Infof("Processing sync for packet %d", *key.PacketID)
	packet, err := parsePacket(*key.Payload)
	if err != nil {
		klog.Infof("Can not process packet %d accepting it: %v", *key.PacketID, err)
		return c.nfq.SetVerdict(*key.PacketID, nfqueue.NfAccept)
	}
	srcIP := packet.srcIP
	srcPort := packet.srcPort
	dstIP := packet.dstIP
	dstPort := packet.dstPort
	protocol := packet.proto

	defer func() {
		histogramVec.WithLabelValues(string(protocol)).Observe(float64(time.Since(startTime).Milliseconds()))
		packetCounterVec.WithLabelValues(string(protocol)).Inc()
		klog.V(0).Infof("Finished syncing packet %d took %v", *key.PacketID, time.Since(startTime))
	}()

	klog.V(0).Infof("Processing packet %s", packet)

	// If no network policies apply traffic is accepted by default
	verdict := true
	var networkPolices []*networkingv1.NetworkPolicy
	var srcPod *v1.Pod
	var selector labels.Selector
	// This uses the source IP and evaluate the policies in Egress
	pods, err := c.getPodsAssignedToIP(srcIP.String())
	if err != nil {
		return err
	}
	// This is an external IP
	if len(pods) == 0 {
		goto INGRESS
	}
	// This is not expected
	if len(pods) > 1 {
		klog.Infof("unexpected number of pods %d", len(pods))
	}
	// Just guess and use the first Pod
	// TODO: use the one that is running if there are multiple it can be possible one got reused
	srcPod = pods[0]
	// Get all the network policies that affect this pod
	selector = labels.SelectorFromSet(labels.Set(map[string]string{
		"kubernetes.io/metadata.name": srcPod.Namespace,
	}))

	networkPolices, err = c.networkpolicyLister.List(selector)
	if err != nil {
		return err
	}

	// verdict is true for accept the connection and false for deny
	// For a connection from a source pod to a destination pod to be allowed,
	// both the egress policy on the source pod and the ingress policy on the
	// destination pod need to allow the connection.
	// If either side does not allow the connection, it will not happen.

	for _, netpol := range networkPolices {
		// podSelector selects the pods to which this NetworkPolicy object applies.
		// The array of ingress rules is applied to any pods selected by this field.
		// Multiple network policies can select the same set of pods. In this case,
		// the ingress rules for each are combined additively.
		// This field is NOT optional and follows standard label selector semantics.
		// An empty podSelector matches all pods in this namespace.
		podSelector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
		if err != nil {
			return err
		}
		// networkPolicy does not selects the pod
		// try the next network policy
		if !podSelector.Matches(labels.Set(srcPod.Labels)) {
			continue
		}
		for _, policyType := range netpol.Spec.PolicyTypes {
			// This is checking the traffic originated from the Pod
			// PolicyTypeIngress does not apply here
			if policyType == networkingv1.PolicyTypeIngress {
				continue
			}

			if policyType == networkingv1.PolicyTypeEgress {
				// egress is a list of egress rules to be applied to the selected pods. Outgoing traffic
				// is allowed if there are no NetworkPolicies selecting the pod (and cluster policy
				// otherwise allows the traffic), OR if the traffic matches at least one egress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
				// solely to ensure that the pods it selects are isolated by default).
				if len(netpol.Spec.Egress) == 0 {
					verdict = false
					continue
				}
				for _, rule := range netpol.Spec.Egress {
					// ports is a list of ports which should be made accessible on the pods selected for
					// this rule. Each item in this list is combined using a logical OR. If this field is
					// empty or missing, this rule matches all ports (traffic not restricted by port).
					// If this field is present and contains at least one item, then this rule allows
					// traffic only if the traffic matches at least one port in the list.
					if len(rule.Ports) > 0 {
						found := false
						for _, port := range rule.Ports {
							if protocol != *port.Protocol {
								continue
							}
							// matches all ports
							if port.Port == nil {
								found = true
								break
							}
							// TODO handle named ports
							if dstPort == port.Port.IntValue() {
								found = true
								break
							}
							// endPort indicates that the range of ports from port to endPort if set, inclusive,
							// should be allowed by the policy. This field cannot be defined if the port field
							// is not defined or if the port field is defined as a named (string) port.
							// The endPort must be equal or greater than port.
							if port.EndPort != nil && dstPort > port.Port.IntValue() && int32(dstPort) <= *port.EndPort {
								found = true
								break
							}
						}
						if !found {
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
						verdict = true
						goto INGRESS
					}
					for _, peer := range rule.To {
						// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
						// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
						// that should not be included within this rule.
						if peer.IPBlock != nil {
							_, cidr, err := net.ParseCIDR(peer.IPBlock.CIDR)
							if err != nil {
								return err
							}
							// TODO check the destination IP is allowed
							if !cidr.Contains(srcIP) {
								verdict = false
								continue
							}

							for _, ipBlock := range peer.IPBlock.Except {
								_, cidr, err := net.ParseCIDR(ipBlock)
								if err != nil {
									return err
								}
								if cidr.Contains(srcIP) {
									verdict = false
									break
								}
							}
							verdict = true
							goto INGRESS
						}

						// podSelector is a label selector which selects pods. This field follows standard label
						// selector semantics; if present but empty, it selects all pods.
						//
						// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
						// Otherwise it selects the pods matching podSelector in the policy's own namespace.
						if peer.PodSelector == nil {
							verdict = false
							continue
						}
						podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
						if err != nil {
							return err
						}
						// networkPolicy does not selects the pod
						// try the next network policy
						if !podSelector.Matches(labels.Set(srcPod.Labels)) {
							verdict = false
							continue
						}

						// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
						// standard label selector semantics; if present but empty, it selects all namespaces.
						//
						// If podSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the namespaces selected by namespaceSelector.
						// Otherwise it selects all pods in the namespaces selected by namespaceSelector.
						if peer.NamespaceSelector == nil || peer.NamespaceSelector.Size() == 0 {
							// SrcPod is in the same namespace as the network policy
							verdict = true
							goto INGRESS
						}
						nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
						if err != nil {
							return err
						}
						namespaces, err := c.namespaceLister.List(nsSelector)
						if err != nil {
							return err
						}
						for _, ns := range namespaces {
							if srcPod.Namespace == ns.Name {
								verdict = true
								goto INGRESS
							}
						}
						verdict = false
						continue
					}
				}

			}
		}
	}

INGRESS:
	var dstPod *v1.Pod
	// This uses the source IP and evaluate the policies in Egress
	pods, err = c.getPodsAssignedToIP(dstIP.String())
	if err != nil {
		return err
	}
	// This is an external IP so no network policies apply
	if len(pods) == 0 {
		goto END
	}
	// This is not expected
	if len(pods) > 1 {
		klog.Infof("unexpected number of pods %d", len(pods))
	}
	// Just guess and use the first Pod
	// TODO: use the one that is running if there are multiple it can be possible one got reused
	dstPod = pods[0]
	// Get all the network policies that affect this pod
	selector = labels.SelectorFromSet(labels.Set(map[string]string{
		"kubernetes.io/metadata.name": dstPod.Namespace,
	}))
	networkPolices, err = c.networkpolicyLister.List(selector)
	if err != nil {
		return err
	}

	for _, netpol := range networkPolices {
		// podSelector selects the pods to which this NetworkPolicy object applies.
		// The array of ingress rules is applied to any pods selected by this field.
		// Multiple network policies can select the same set of pods. In this case,
		// the ingress rules for each are combined additively.
		// This field is NOT optional and follows standard label selector semantics.
		// An empty podSelector matches all pods in this namespace.
		podSelector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
		if err != nil {
			return err
		}
		// networkPolicy does not selects the pod
		// try the next network policy
		if !podSelector.Matches(labels.Set(dstPod.Labels)) {
			continue
		}
		for _, policyType := range netpol.Spec.PolicyTypes {
			// This is checking the traffic destined to the Pod
			// PolicyTypeEgress does not apply here
			if policyType == networkingv1.PolicyTypeEgress {
				continue
			}

			if policyType == networkingv1.PolicyTypeIngress {
				// ingress is a list of ingress rules to be applied to the selected pods.
				// Traffic is allowed to a pod if there are no NetworkPolicies selecting the pod
				// (and cluster policy otherwise allows the traffic), OR if the traffic source is
				// the pod's local node, OR if the traffic matches at least one ingress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy does not allow any traffic (and serves
				// solely to ensure that the pods it selects are isolated by default)
				if len(netpol.Spec.Ingress) == 0 {
					verdict = false
					continue
				}
				for _, rule := range netpol.Spec.Ingress {
					// ports is a list of ports which should be made accessible on the pods selected for
					// this rule. Each item in this list is combined using a logical OR. If this field is
					// empty or missing, this rule matches all ports (traffic not restricted by port).
					// If this field is present and contains at least one item, then this rule allows
					// traffic only if the traffic matches at least one port in the list.
					if len(rule.Ports) > 0 {
						found := false
						for _, port := range rule.Ports {
							if protocol != *port.Protocol {
								continue
							}
							// matches all ports
							if port.Port == nil {
								found = true
								break
							}
							// TODO handle named ports
							if srcPort == port.Port.IntValue() {
								found = true
								break
							}
							// endPort indicates that the range of ports from port to endPort if set, inclusive,
							// should be allowed by the policy. This field cannot be defined if the port field
							// is not defined or if the port field is defined as a named (string) port.
							// The endPort must be equal or greater than port.
							if port.EndPort != nil && srcPort > port.Port.IntValue() && int32(srcPort) <= *port.EndPort {
								found = true
								break
							}
						}
						if !found {
							verdict = false
							continue
						}
					}
					// from is a list of sources which should be able to access the pods selected for this rule.
					// Items in this list are combined using a logical OR operation. If this field is
					// empty or missing, this rule matches all sources (traffic not restricted by
					// source). If this field is present and contains at least one item, this rule
					// allows traffic only if the traffic matches at least one item in the from list.
					if len(rule.From) == 0 {
						verdict = true
						goto END
					}
					for _, peer := range rule.From {
						// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
						// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
						// that should not be included within this rule.
						if peer.IPBlock != nil {
							_, cidr, err := net.ParseCIDR(peer.IPBlock.CIDR)
							if err != nil {
								return err
							}
							// TODO check the destination IP is allowed
							if !cidr.Contains(srcIP) {
								verdict = false
								continue
							}

							for _, ipBlock := range peer.IPBlock.Except {
								_, cidr, err := net.ParseCIDR(ipBlock)
								if err != nil {
									return err
								}
								if cidr.Contains(srcIP) {
									verdict = false
									break
								}
							}

							verdict = true
							goto END
						}

						// podSelector is a label selector which selects pods. This field follows standard label
						// selector semantics; if present but empty, it selects all pods.
						//
						// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
						// Otherwise it selects the pods matching podSelector in the policy's own namespace.
						if peer.PodSelector == nil {
							verdict = false
							continue
						}
						podSelector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
						if err != nil {
							return err
						}
						// networkPolicy does not selects the pod
						// try the next network policy
						if !podSelector.Matches(labels.Set(srcPod.Labels)) {
							verdict = false
							continue
						}

						// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
						// standard label selector semantics; if present but empty, it selects all namespaces.
						//
						// If podSelector is also set, then the NetworkPolicyPeer as a whole selects
						// the pods matching podSelector in the namespaces selected by namespaceSelector.
						// Otherwise it selects all pods in the namespaces selected by namespaceSelector.
						if peer.NamespaceSelector == nil || peer.NamespaceSelector.Size() == 0 {
							// SrcPod is in the same namespace as the network policy
							verdict = true
							goto END
						}
						nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
						if err != nil {
							return err
						}
						namespaces, err := c.namespaceLister.List(nsSelector)
						if err != nil {
							return err
						}
						for _, ns := range namespaces {
							if srcPod.Namespace == ns.Name {
								verdict = true
								goto END
							}
						}
						verdict = false
						continue
					}
				}

			}
		}
	}
END:
	if verdict {
		return c.nfq.SetVerdict(*key.PacketID, nfqueue.NfAccept)
	}
	return c.nfq.SetVerdict(*key.PacketID, nfqueue.NfDrop)
}

type tuple struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort int
	dstPort int
	proto   v1.Protocol
}

func (t tuple) String() string {
	return fmt.Sprintf("%s:%d %s:%d %s", t.srcIP.String(), t.srcPort, t.dstIP.String(), t.dstPort, t.proto)
}

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
// https://en.wikipedia.org/wiki/IPv6_packet
// https://github.com/golang/net/blob/master/ipv4/header.go
func parsePacket(b []byte) (tuple, error) {
	t := tuple{}
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
	return t, nil
}

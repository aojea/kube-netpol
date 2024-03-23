package networkpolicy

import (
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

const (
	// maxRetries is the number of times a object will be retried before it is dropped out of the queue.
	// With the current rate-limiter in use (5ms*2^(maxRetries-1)) the following numbers represent the
	// sequence of delays between successive queuings of an object.
	//
	// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1.3s, 2.6s, 5.1s, 10.2s, 20.4s, 41s, 82s
	maxRetries = 15

	controllerName = "kubernetes-networkpolicy-controller"
)

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	reconciler Reconciler,
) *Controller {
	klog.V(4).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	c := &Controller{
		client:           client,
		reconciler:       reconciler,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), controllerName),
		workerLoopPeriod: time.Second,
	}

	// network policies
	klog.Info("Setting up event handlers for network policies")
	networkpolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNetworkPolicyAdd,
		UpdateFunc: c.onNetworkPolicyUpdate,
		DeleteFunc: c.onNetworkPolicyDelete,
	})
	c.networkpolicyLister = networkpolicyInformer.Lister()
	c.networkpoliciesSynced = networkpolicyInformer.Informer().HasSynced

	// namespaces
	klog.Info("Setting up event handlers for namespaces")
	namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNamespaceAdd,
		UpdateFunc: c.onNamespaceUpdate,
		DeleteFunc: c.onNamespaceDelete,
	})

	c.namespaceLister = namespaceInformer.Lister()
	c.namespacesSynced = namespaceInformer.Informer().HasSynced

	// pods
	klog.Info("Setting up event handlers for pods")
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onPodAdd,
		UpdateFunc: c.onPodUpdate,
		DeleteFunc: c.onPodDelete,
	})

	c.podLister = podInformer.Lister()
	c.podsSynced = podInformer.Informer().HasSynced

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

	// interface to apply network policies to the data plane
	reconciler Reconciler

	// rate limited queue
	queue workqueue.RateLimitingInterface

	// workerLoopPeriod is the time between worker runs. The workers process the queue of networkpolicy and pod changes.
	workerLoopPeriod time.Duration
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting controller %s", controllerName)
	defer klog.Infof("Shutting down controller %s", controllerName)

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.networkpoliciesSynced, c.namespacesSynced, c.podsSynced) {
		return fmt.Errorf("error syncing cache")
	}

	// Start the workers after the repair loop to avoid races
	klog.Info("Starting workers")
	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, stopCh)
	}

	<-stopCh
	return nil
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

	err := c.syncNetworkPolicy(eKey.(string))
	c.handleErr(err, eKey)

	return true
}

func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	ns, name, keyErr := cache.SplitMetaNamespaceKey(key.(string))
	if keyErr != nil {
		klog.ErrorS(err, "Failed to split meta namespace cache key", "key", key)
	}

	// MetricRequeueNetworkPolicyCount.WithLabelValues(key.(string)).Inc()

	if c.queue.NumRequeues(key) < maxRetries {
		klog.V(2).InfoS("Error syncing networkpolicy, retrying", "networkpolicy", klog.KRef(ns, name), "err", err)
		c.queue.AddRateLimited(key)
		return
	}

	klog.Warningf("Dropping network policy %q out of the queue: %v", key, err)
	c.queue.Forget(key)
	utilruntime.HandleError(err)
}

func (c *Controller) syncNetworkPolicy(key string) error {
	startTime := time.Now()
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	klog.Infof("Processing sync for network policy %s on namespace %s ", name, namespace)
	// MetricSyncNetworkPolicyCount.WithLabelValues(key).Inc()

	defer func() {
		klog.V(4).Infof("Finished syncing network policy %s on namespace %s : %v", name, namespace, time.Since(startTime))
		// MetricSyncNetworkPolicyLatency.WithLabelValues(key).Observe(time.Since(startTime).Seconds())
	}()

	// Get current NetworkPolicy from the cache
	networkpolicy, err := c.networkpolicyLister.NetworkPolicies(namespace).Get(name)
	// It´s unlikely that we have an error different that "Not Found Object"
	// because we are getting the object from the informer´s cache
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	// Delete the network policy, it no longer exists
	if err != nil {
		return c.reconciler.Reconcile(key, Policy{})
	}

	// Get desired state for the network policy
	// This assumes that the implementation of the network policier knows
	// how to handle the differences. Per example, if a network policy is
	// updated the network policier should handle the transition from
	// current state to desired state.
	klog.Infof("Creating networkpolicy %s on namespace %s", name, namespace)
	klog.Infof("Network Policy %+v", networkpolicy)

	// This selects particular Pods in the same namespace as the NetworkPolicy which
	// should be allowed as ingress sources or egress destinations.
	podSelector, err := metav1.LabelSelectorAsSelector(&networkpolicy.Spec.PodSelector)
	if err != nil {
		return err
	}
	pods, err := c.podLister.Pods(namespace).List(podSelector)
	if err != nil {
		return err
	}

	targetIPs := []string{}
	for _, pod := range pods {
		targetIPs = append(targetIPs, getPodIPNets(pod.Status)...)
	}
	klog.Infof("Network Policy %s/%s select pod IPs: %v", networkpolicy.Namespace, networkpolicy.Name, targetIPs)

	// policyTypes: Each NetworkPolicy includes a policyTypes list which may include
	// either Ingress, Egress, or both. The policyTypes field indicates whether or not
	// the given policy applies to ingress traffic to selected pod, egress traffic from
	// selected pods, or both. If no policyTypes are specified on a NetworkPolicy then
	// by default Ingress will always be set and Egress will be set if the NetworkPolicy
	// has any egress rules.
	newPolicy := Policy{
		Name:          key,
		DefaultAction: DropAction,
	}
	allowedIPs := []string{}
	notAllowedIPs := []string{}

	for _, policyType := range networkpolicy.Spec.PolicyTypes {
		// ingress: Each NetworkPolicy may include a list of allowed ingress rules.
		// Each rule allows traffic which matches both the from and ports sections.
		// The example policy contains a single rule, which matches traffic on a single port,
		// from one of three sources, the first specified via an ipBlock,
		// the second via a namespaceSelector and the third via a podSelector.
		if policyType == networkingv1.PolicyTypeIngress {
			// Default deny all ingress traffic
			if networkpolicy.Spec.Ingress == nil {
				newPolicy.AccessList = append(newPolicy.AccessList, ACL{
					source:      []string{"0.0.0.0/0"},
					destination: targetIPs,
					action:      DropAction,
				})
				continue
			}
			// Default allow all ingress traffic
			if len(networkpolicy.Spec.Ingress) == 0 {
				newPolicy.AccessList = append(newPolicy.AccessList, ACL{
					source:      []string{"0.0.0.0/0"},
					destination: targetIPs,
					action:      PassAction,
				})
				continue
			}

			for _, ingress := range networkpolicy.Spec.Ingress {

				for _, from := range ingress.From {
					nsSelector, err := metav1.LabelSelectorAsSelector(from.NamespaceSelector)
					if err != nil {
						return err
					}

					namespaces, err := c.namespaceLister.List(nsSelector)
					if err != nil {
						return err
					}

					podSelector, err := metav1.LabelSelectorAsSelector(&networkpolicy.Spec.PodSelector)
					if err != nil {
						return err
					}

					allowedIPs = []string{}
					notAllowedIPs = []string{}
					for _, ns := range namespaces {
						pods, err := c.podLister.Pods(ns.String()).List(podSelector)
						if err != nil {
							return err
						}
						for _, pod := range pods {
							allowedIPs = append(allowedIPs, getPodIPNets(pod.Status)...)
						}
					}
					klog.Infof("Network Policy %s/%s Ingress pod IPs: %v", networkpolicy.Namespace, networkpolicy.Name, allowedIPs)

					// This selects particular IP CIDR ranges to allow as ingress sources or egress destinations
					if from.IPBlock != nil {
						klog.Infof("Network Policy %s/%s Ingress IPBlock: %v", networkpolicy.Namespace, networkpolicy.Name, from.IPBlock)
						allowedIPs = append(allowedIPs, from.IPBlock.CIDR)
						notAllowedIPs = from.IPBlock.Except
					}
				}

				ports := []ACLPort{}
				for _, port := range ingress.Ports {
					klog.Infof("Network Policy %s/%s Ingress ports: %v", networkpolicy.Namespace, networkpolicy.Name, port.String())
					ports = append(ports, ACLPort{
						port.Port.String(),
						*port.Protocol,
					})
				}
				// Create ACLs entries
				newPolicy.AccessList = append(newPolicy.AccessList, ACL{
					source:          allowedIPs,
					destination:     targetIPs,
					destinationPort: ports,
					action:          PassAction,
				})
				if len(notAllowedIPs) > 0 {
					newPolicy.AccessList = append(newPolicy.AccessList, ACL{
						source:          notAllowedIPs,
						destination:     targetIPs,
						destinationPort: ports,
						action:          DropAction,
					})
				}

			}
		}
		// egress: Each NetworkPolicy may include a list of allowed egress rules.
		// Each rule allows traffic which matches both the to and ports sections.
		// The example policy contains a single rule, which matches traffic on a
		// single port to any destination in 10.0.0.0/24.
		if policyType == networkingv1.PolicyTypeEgress {
			// Default deny all egress traffic
			if networkpolicy.Spec.Egress == nil {
				newPolicy.AccessList = append(newPolicy.AccessList, ACL{
					source:      targetIPs,
					destination: []string{"0.0.0.0/0"},
					action:      DropAction,
				})
				continue
			}
			// Default allow all egress traffic
			if len(networkpolicy.Spec.Egress) == 0 {
				newPolicy.AccessList = append(newPolicy.AccessList, ACL{
					source:      targetIPs,
					destination: []string{"0.0.0.0/0"},
					action:      PassAction,
				})
				continue
			}

			for _, egress := range networkpolicy.Spec.Egress {
				for _, to := range egress.To {
					nsSelector, err := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
					if err != nil {
						return err
					}

					namespaces, err := c.namespaceLister.List(nsSelector)
					if err != nil {
						return err
					}

					podSelector, err := metav1.LabelSelectorAsSelector(&networkpolicy.Spec.PodSelector)
					if err != nil {
						return err
					}

					allowedIPs = []string{}
					notAllowedIPs = []string{}
					for _, ns := range namespaces {
						pods, err := c.podLister.Pods(ns.String()).List(podSelector)
						if err != nil {
							return err
						}
						for _, pod := range pods {
							allowedIPs = append(allowedIPs, getPodIPNets(pod.Status)...)
						}
					}
					klog.Infof("Network Policy %s/%s Egress pod IPs: %v", networkpolicy.Namespace, networkpolicy.Name, allowedIPs)

					// This selects particular IP CIDR ranges to allow as ingress sources or egress destinations
					if to.IPBlock != nil {
						klog.Infof("Network Policy %s/%s Egress IPBlock: %v", networkpolicy.Namespace, networkpolicy.Name, to.IPBlock)
						allowedIPs = append(allowedIPs, to.IPBlock.CIDR)
						notAllowedIPs = to.IPBlock.Except
					}
				}

				ports := []ACLPort{}
				for _, port := range egress.Ports {
					klog.Infof("Network Policy %s/%s Egress ports: %v", networkpolicy.Namespace, networkpolicy.Name, port.String())
					ports = append(ports, ACLPort{
						port.Port.String(),
						*port.Protocol,
					})
				}
				// Create ACLs entries
				newPolicy.AccessList = append(newPolicy.AccessList, ACL{
					source:          targetIPs,
					destination:     allowedIPs,
					destinationPort: ports,
					action:          PassAction,
				})
				if len(notAllowedIPs) > 0 {
					newPolicy.AccessList = append(newPolicy.AccessList, ACL{
						source:          targetIPs,
						destination:     notAllowedIPs,
						destinationPort: ports,
						action:          DropAction,
					})
				}

			}
		}
	}
	return c.reconciler.Reconcile(key, newPolicy)
}

// handlers

// onNetworkPolicyUpdate queues the NetworkPolicy for processing.
func (c *Controller) onNetworkPolicyAdd(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	klog.V(4).Infof("Adding networkpolicy %s", key)
	c.queue.Add(key)
}

// onNetworkPolicyUpdate updates the NetworkPolicy Selector in the cache and queues the NetworkPolicy for processing.
func (c *Controller) onNetworkPolicyUpdate(oldObj, newObj interface{}) {
	oldNetworkPolicy := oldObj.(*networkingv1.NetworkPolicy)
	newNetworkPolicy := newObj.(*networkingv1.NetworkPolicy)

	// don't process resync or objects that are marked for deletion
	if oldNetworkPolicy.ResourceVersion == newNetworkPolicy.ResourceVersion ||
		!newNetworkPolicy.GetDeletionTimestamp().IsZero() {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err == nil {
		c.queue.Add(key)
	}
}

// onNetworkPolicyDelete queues the NetworkPolicy for processing.
func (c *Controller) onNetworkPolicyDelete(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	klog.V(4).Infof("Deleting networkpolicy %s", key)
	c.queue.Add(key)
}

// onNamespaceAdd queues a sync for the relevant NetworkPolicy for a sync
func (c *Controller) onNamespaceAdd(obj interface{}) {
	namespace := obj.(*v1.Namespace)
	if namespace == nil {
		utilruntime.HandleError(fmt.Errorf("invalid Namespace provided to onNamespaceAdd()"))
		return
	}
	c.queueNetworkPoliciesForNamespace(namespace)
}

// onNamespaceUpdate queues a sync for the relevant NetworkPolicy for a sync
func (c *Controller) onNamespaceUpdate(prevObj, obj interface{}) {
	prevNamespace := prevObj.(*v1.Namespace)
	namespace := obj.(*v1.Namespace)

	// don't process resync or objects that are marked for deletion
	if prevNamespace.ResourceVersion == namespace.ResourceVersion ||
		!namespace.GetDeletionTimestamp().IsZero() {
		return
	}
	c.queueNetworkPoliciesForNamespace(namespace)
}

// onNamespaceDelete queues a sync for the relevant NetworkPolicy for a sync if the
// EndpointSlice resource version does not match the expected version in the
// namespaceTracker.
func (c *Controller) onNamespaceDelete(obj interface{}) {
	namespace, ok := obj.(*v1.Namespace)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		namespace, ok = tombstone.Obj.(*v1.Namespace)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a EndpointSlice: %#v", obj))
			return
		}
	}

	if namespace != nil {
		c.queueNetworkPoliciesForNamespace(namespace)
	}
}

// queueNetworkPoliciesForNamespace queue the network policies affected by the namespace changes
func (c *Controller) queueNetworkPoliciesForNamespace(namespace *v1.Namespace) {
	nsLabels := labels.Set(namespace.GetLabels())
	networkpolicies, err := c.networkpolicyLister.List(labels.Everything())
	if err != nil {
		return
	}
	for _, np := range networkpolicies {
		// enqueue all the network policies that affect the namespace
		for _, ingress := range np.Spec.Ingress {
			for _, from := range ingress.From {
				nsSelector, err := metav1.LabelSelectorAsSelector(from.NamespaceSelector)
				if err != nil {
					continue
				}
				if nsSelector.Matches(nsLabels) {
					key, err := cache.MetaNamespaceKeyFunc(np)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", np, err))
						return
					}
					c.queue.Add(key)
				}
			}
		}
		for _, egress := range np.Spec.Egress {
			for _, to := range egress.To {
				nsSelector, err := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
				if err != nil {
					continue
				}
				if nsSelector.Matches(nsLabels) {
					key, err := cache.MetaNamespaceKeyFunc(np)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", np, err))
						return
					}
					c.queue.Add(key)
				}
			}
		}
	}
}

// onPodAdd queues a sync for the relevant NetworkPolicy for a sync
func (c *Controller) onPodAdd(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod == nil {
		utilruntime.HandleError(fmt.Errorf("invalid EndpointSlice provided to onPodAdd()"))
		return
	}
	c.queueNetworkPoliciesForPod(pod)
}

// onPodUpdate queues a sync for the relevant NetworkPolicy for a sync
func (c *Controller) onPodUpdate(prevObj, obj interface{}) {
	prevPod := prevObj.(*v1.Pod)
	pod := obj.(*v1.Pod)

	// don't process resync or objects that are marked for deletion
	if prevPod.ResourceVersion == pod.ResourceVersion ||
		!pod.GetDeletionTimestamp().IsZero() {
		return
	}
	c.queueNetworkPoliciesForPod(pod)
}

// onPodDelete queues a sync for the relevant NetworkPolicy for a sync if the
// EndpointSlice resource version does not match the expected version in the
// namespaceTracker.
func (c *Controller) onPodDelete(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Pod: %#v", obj))
			return
		}
	}

	if pod != nil {
		c.queueNetworkPoliciesForPod(pod)
	}
}

// queueNetworkPolicyForEndpointSlice attempts to queue the corresponding NetworkPolicy for
// the provided EndpointSlice.
func (c *Controller) queueNetworkPoliciesForPod(pod *v1.Pod) {
	podLabels := labels.Set(pod.GetLabels())
	namespace, err := c.namespaceLister.Get(pod.Namespace)
	if err != nil {
		return
	}
	nsLabels := labels.Set(namespace.GetLabels())
	networkpolicies, err := c.networkpolicyLister.List(labels.Everything())
	if err != nil {
		return
	}
	for _, np := range networkpolicies {
		if np.Namespace == pod.Namespace {
			podSelector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			if err != nil {
				continue
			}
			if podSelector.Matches(podLabels) {
				key, err := cache.MetaNamespaceKeyFunc(np)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", np, err))
					return
				}
				c.queue.Add(key)
			}
		}
		// enqueue all the network policies that affect the pod
		for _, ingress := range np.Spec.Ingress {
			for _, from := range ingress.From {
				nsSelector, err := metav1.LabelSelectorAsSelector(from.NamespaceSelector)
				if err != nil {
					continue
				}
				if !nsSelector.Matches(nsLabels) {
					continue
				}
				podSelector, err := metav1.LabelSelectorAsSelector(from.PodSelector)
				if err != nil {
					continue
				}
				if podSelector.Matches(podLabels) {
					key, err := cache.MetaNamespaceKeyFunc(np)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", np, err))
						return
					}
					c.queue.Add(key)
				}

			}
		}
		for _, egress := range np.Spec.Egress {
			for _, to := range egress.To {
				nsSelector, err := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
				if err != nil {
					continue
				}
				if !nsSelector.Matches(nsLabels) {
					continue
				}
				podSelector, err := metav1.LabelSelectorAsSelector(to.PodSelector)
				if err != nil {
					continue
				}
				if podSelector.Matches(podLabels) {
					key, err := cache.MetaNamespaceKeyFunc(np)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", np, err))
						return
					}
					c.queue.Add(key)
				}
			}
		}
	}
}

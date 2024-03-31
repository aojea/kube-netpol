package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"

	"github.com/aojea/kube-netpol/pkg/networkpolicy"
	"github.com/coreos/go-iptables/iptables"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

func main() {
	// enable logging
	klog.InitFlags(nil)
	flag.Parse()
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":9080", nil)

	// Install iptables rule to handle IPv4 traffic
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err == nil {
		klog.Infof("Running on IPv4 mode")
		networkPolicyController4 := networkpolicy.NewController(
			clientset,
			informersFactory.Networking().V1().NetworkPolicies(),
			informersFactory.Core().V1().Namespaces(),
			informersFactory.Core().V1().Pods(),
			ipt4,
			104,
		)
		go networkPolicyController4.Run(ctx, 5)
	} else {
		klog.Infof("Error running on IPv4 mode: %v", err)
	}

	/* TODO make this configurable, it can be ipv4, ipv6 or dual
	ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Fatalf("Could not use iptables IPv6: %v", err)
	}
	*/

	ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err == nil {
		klog.Infof("Running on IPv6 mode")
		networkPolicyController6 := networkpolicy.NewController(
			clientset,
			informersFactory.Networking().V1().NetworkPolicies(),
			informersFactory.Core().V1().Namespaces(),
			informersFactory.Core().V1().Pods(),
			ipt6,
			106,
		)
		go networkPolicyController6.Run(ctx, 5)
	} else {
		klog.Infof("Error running on IPv6 mode: %v", err)
	}

	informersFactory.Start(ctx.Done())

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

}

package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"

	"github.com/aojea/kube-netpol/pkg/networkpolicy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
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

	nft, err := knftables.New(knftables.InetFamily, "kube-netpol")
	if err != nil {
		klog.Fatalf("Error initializing nftables: %v", err)
	}

	networkPolicyController := networkpolicy.NewController(
		clientset,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		nft,
		104,
	)
	go networkPolicyController.Run(ctx, 5)

	informersFactory.Start(ctx.Done())

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

}

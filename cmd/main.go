package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/aojea/kube-netpol/pkg/networkpolicy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

var (
	failOpen bool
	queueID  int
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running (default false)")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used (default 100)")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-netpol [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// enable logging
	klog.InitFlags(nil)
	flag.Parse()
	//
	cfg := networkpolicy.Config{
		FailOpen: failOpen,
		QueueID:  queueID,
	}
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

	networkPolicyController := networkpolicy.NewController(
		clientset,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		cfg,
	)
	go networkPolicyController.Run(ctx)

	informersFactory.Start(ctx.Done())

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
}

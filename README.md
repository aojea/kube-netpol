# kube-netpol

Network policies are hard to implement efficiently and in large clusters this is translated to performance and scalability problems.

Most of the existing implementation use the same approach of processing the APIs and transforming them in the corresponding dataplane implementation: iptables, nftables, ebpf or ovs, ...

This project takes a different approach, it uses the NFQUEUE functionality implemented in netfilter to process he first packet of each connection in userspace and emit a veredict. The advantages is that the dataplane implementation does not need to represent all the complex logic, allowing to scale better, the disadvantage is that we need to pass each new connection packet through userspace.

There are some performance improvements that can be applied, as to restrict in the dataplane the packets that are sent touserspace to the ones that have network policies only, so only
the Pods affected by network policies will hit the first byte performance.


## References

* https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
* https://netfilter.org/projects/libnetfilter_queue/doxygen/html/
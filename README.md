# kube-netpol

Network policies are hard to implement efficiently and in large clusters this is translated to performance and scalability problems.

Most of the existing implementations use the same approach of processing the APIs and transforming them in the corresponding dataplane implementation: iptables, nftables, ebpf or ovs, ...

This project takes a different approach. It uses the NFQUEUE functionality implemented in netfilter to process the first packet of each connection in userspace and emit a verdict. The advantage is that the dataplane implementation does not need to represent all the complex logic, allowing it to scale better. The disadvantage is that we need to pass each new connection packet through userspace.

There are some performance improvements that can be applied, such as to restrict in the dataplane the packets that are sent to userspace to the ones that have network policies only, so only
the Pods affected by network policies will hit the first byte performance.


## References

* https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
* https://netfilter.org/projects/libnetfilter_queue/doxygen/html/

--- ./net/ipv4/udp.c	2002/02/26 14:54:22	1.2
+++ ./net/ipv4/udp.c	2002/05/22 12:14:58
@@ -777,6 +777,9 @@
 
 static int udp_queue_rcv_skb(struct sock * sk, struct sk_buff *skb)
 {
+#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
+	struct udp_opt *tp =  &(sk->tp_pinfo.af_udp);
+#endif
 	/*
 	 *	Charge it to the socket, dropping if the queue is full.
 	 */
@@ -794,6 +797,38 @@
 	}
 #endif
 
+#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
+	if (tp->esp_in_udp) {
+		/*
+		 * Set skb->sk and xmit packet to ipsec_rcv.
+		 *
+		 * If ret != 0, ipsec_rcv refused the packet (not ESPinUDP),
+		 * restore skb->sk and fall back to sock_queue_rcv_skb
+		 */
+		struct inet_protocol *esp = NULL;
+
+#ifdef CONFIG_IPSEC_MODULE
+		for (esp = (struct inet_protocol *)inet_protos[IPPROTO_ESP & (MAX_INET_PROTOS - 1)];
+			(esp) && (esp->protocol != IPPROTO_ESP);
+			esp = esp->next);
+#else
+		extern struct inet_protocol esp_protocol;
+		esp = &esp_protocol;
+#endif
+
+		if (esp && esp->handler) {
+			struct sock *sav_sk = skb->sk;
+			skb->sk = sk;
+			if (esp->handler(skb) == 0) {
+				skb->sk = sav_sk;
+				/* not sure we might count ESPinUDP as UDP... */
+				UDP_INC_STATS_BH(UdpInDatagrams);
+				return 0;
+			}
+			skb->sk = sav_sk;
+		}
+	}
+#endif
 	if (sock_queue_rcv_skb(sk,skb)<0) {
 		UDP_INC_STATS_BH(UdpInErrors);
 		IP_INC_STATS_BH(IpInDiscards);
@@ -1010,13 +1045,55 @@
 	return len;
 }
 
+#if 1
+static int udp_setsockopt(struct sock *sk, int level, int optname,
+	char *optval, int optlen)
+{
+	struct udp_opt *tp = &(sk->tp_pinfo.af_udp);
+	int val;
+	int err = 0;
+
+	if (level != SOL_UDP)
+		return ip_setsockopt(sk, level, optname, optval, optlen);
+
+	if(optlen<sizeof(int))
+		return -EINVAL;
+
+	if (get_user(val, (int *)optval))
+		return -EFAULT;
+	
+	lock_sock(sk);
+
+	switch(optname) {
+#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
+#ifndef UDP_ESPINUDP
+#define UDP_ESPINUDP 100
+#endif
+		case UDP_ESPINUDP:
+			tp->esp_in_udp = val;
+			break;
+#endif
+		default:
+			err = -ENOPROTOOPT;
+			break;
+	}
+
+	release_sock(sk);
+	return err;
+}
+#endif
+
 struct proto udp_prot = {
  	name:		"UDP",
 	close:		udp_close,
 	connect:	udp_connect,
 	disconnect:	udp_disconnect,
 	ioctl:		udp_ioctl,
+#if 1
+	setsockopt:	udp_setsockopt,
+#else
 	setsockopt:	ip_setsockopt,
+#endif
 	getsockopt:	ip_getsockopt,
 	sendmsg:	udp_sendmsg,
 	recvmsg:	udp_recvmsg,

--- ./include/net/sock.h	Fri Nov  2 17:39:16 2001
+++ ./include/net/sock.h	Mon Jun 10 19:44:55 2002
@@ -201,6 +201,12 @@
 	__u32	end_seq;
 };
 
+#if 1
+struct udp_opt {
+	__u32 esp_in_udp;
+};
+#endif
+
 struct tcp_opt {
 	int	tcp_header_len;	/* Bytes of tcp header to send		*/
 
@@ -443,6 +449,9 @@
 #if defined(CONFIG_SPX) || defined (CONFIG_SPX_MODULE)
 		struct spx_opt		af_spx;
 #endif /* CONFIG_SPX */
+#if 1
+		struct udp_opt 		af_udp;
+#endif
 
 	} tp_pinfo;
 

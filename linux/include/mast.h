struct mast_callbacks {
  int (*packet_encap)(struct device *mast, void *context,
		      struct sk_buff *skb, int flowref);
  int (*link_inquire)(struct device *mast, void *context);
};


struct device *mast_init (int family,
			  struct mast_callbacks *callbacks,
			  unsigned int flags,
			  unsigned int desired_unit,
			  unsigned int max_flowref,
			  void *context);

int mast_destroy(struct device *mast);

int mast_recv(struct device *mast, struct sk_buff *skb, int flowref);

/* free this skb as being useless, increment failure count. */
int mast_toast(struct device *mast, struct sk_buff *skb, int flowref);

int mast_linkstat (struct device *mast, int flowref,
		   int status);

int mast_setreference (struct device *mast,
		       int defaultSA);

int mast_setneighbor (struct device *mast,
		      struct sockaddr *source,
		      struct sockaddr *destination,
		      int flowref);



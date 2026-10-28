#include <daemon.h>
#include <library.h>
#include <config/ike_cfg.h>
#include <config/peer_cfg.h>
#include <crypto/proposal/proposal.h>
#include <encoding/message.h>
#include <networking/host.h>
#include <networking/packet.h>
#include <sa/ike_sa_id.h>
#include <sa/ike_sa.h>
#include <sa/ikev2/tasks/ike_init.h>
#include <sa/task.h>
#include <utils/chunk.h>
#include <utils/debug.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_ike_init");
	if (!lib->plugins->load(lib->plugins, PLUGINS " nonce"))
	{
		return 1;
	}
	libcharon_init();

#if 0
	/* useful for debugging */
	level_t levels[DBG_MAX];
	for (unsigned int i = 0; i < DBG_MAX; i++)
	{
		levels[i] = LEVEL_RAW;
	}
	charon->set_default_loggers(charon, levels, TRUE);
	charon->load_loggers(charon);
#endif

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	ike_sa_id_t *ike_sa_id;
	ike_sa_t *ike_sa;
	ike_init_t *ike_init;
	message_t *message;
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	host_t *my_host;
	host_t *other_host;
	uint64_t initiator_spi = 0x1, responder_spi = 0x2;
	chunk_t chunk = chunk_create((u_char*)buf, len);
	ike_cfg_create_t ike_cfg_data = {
		.version = IKEV2,
		.local = "127.0.0.1",
		.local_port = 500,
		.remote = "127.0.0.1",
		.remote_port = 500,
		.no_certreq = true,
		.ocsp_certreq = true,
		.fragmentation = FRAGMENTATION_YES,
		.childless = CHILDLESS_ALLOW,
		.dscp = 0U
	};
	peer_cfg_create_t peer_cfg_data = {
		.options = OPT_PPK_REQUIRED,
		.cert_policy = CERT_SEND_IF_ASKED,
		.ocsp_policy = OCSP_SEND_BOTH,
		.unique = UNIQUE_REPLACE,
		.keyingtries = 3U,
		.rekey_time = 3U,
		.reauth_time = 3U,
		.jitter_time = 3U,
		.over_time = 3U,
		.dpd = 3U,
		.dpd_timeout= 0U,
		.if_id_in= 0U,
		.if_id_out= 0U,
		/* if ppk_id is stack junk, there will be a crash */
		.ppk_id = NULL,
	};

	ike_cfg = ike_cfg_create(&ike_cfg_data);
	if (ike_cfg)
	{
		ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
		ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_AH));
		ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_ESP));
		ike_cfg->add_proposal(ike_cfg, proposal_create_default_aead(PROTO_ESP));

		peer_cfg = peer_cfg_create("fuzz_peer", ike_cfg, &peer_cfg_data);
		if (peer_cfg)
		{
			my_host = host_create_from_string("192.0.2.1", 500);
			other_host = host_create_from_string("192.0.2.2", 500);
			if (my_host && other_host)
			{
				ike_sa_id = ike_sa_id_create(2, initiator_spi, responder_spi, TRUE);
				if (ike_sa_id)
				{
					ike_sa = ike_sa_create(ike_sa_id, TRUE, 2);
					if (ike_sa)
					{
						ike_sa->set_my_host(ike_sa, my_host);
						ike_sa->set_other_host(ike_sa, other_host);
						ike_sa->set_peer_cfg(ike_sa, peer_cfg);
						ike_sa->set_ike_cfg(ike_sa, ike_cfg);

						message = message_create_from_packet(
							packet_create_from_data(
								my_host->clone(my_host),
								other_host->clone(other_host),
								chunk_clone(chunk)
							)
						);

						if (message->parse_header(message) == SUCCESS)
						{
							message->parse_body(message, NULL);

							ike_init = ike_init_create(ike_sa, TRUE, NULL);
							if (ike_init)
							{
								if (ike_init->task.pre_process)
									ike_init->task.pre_process(&ike_init->task, message);

								ike_init->task.process(&ike_init->task, message);

								if (ike_init->task.post_process)
									ike_init->task.post_process(&ike_init->task, message);

								ike_init->task.build(&ike_init->task, message);

								if (ike_init->task.post_build)
									ike_init->task.post_build(&ike_init->task, message);

								ike_init->task.destroy(&ike_init->task);
							}
						}

						message->destroy(message);
						ike_sa->destroy(ike_sa);
					}
					ike_sa_id->destroy(ike_sa_id);
				}
			}

			// free()'s ike_cfg
			peer_cfg->destroy(peer_cfg);
		}
	}

	return 0;
}

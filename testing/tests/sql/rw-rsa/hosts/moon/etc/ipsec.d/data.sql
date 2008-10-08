/* Identities */

INSERT INTO identities (
  type, data
) VALUES ( /* moon.strongswan.org */
  2, X'6d6f6f6e2e7374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* carol@strongswan.org */
  3, X'6361726f6c407374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* dave@strongswan.org */
  3, X'64617665407374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* %any */
  0, '%any'
);

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of moon.strongswan.org */
  202, X'd70dbd46d5133519064f12f100525ead0802ca95'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of carol@strongswan.org */
  202, X'985c23660cd9b9a7554da6a4aa31ea02230fd482'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of dave@strongswan.org */
  202, X'f651b7ea33148cc5a76a622f1c1eb16c6bbdea25'
 );

/* Raw RSA public keys */

INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* moon.strongswan.org */
  6, 1, X'30820122300d06092a864886f70d01010105000382010f003082010a0282010100afae2e109ac0a71b437b6f1a9e5194d085c999fe2c8de11b261f016c88e734eb1a6767b15bc7d8338bf3acc14e8a18bf857fd3dfbce637e9b0d3654f15d9068bdf4450517cf72651be8d4c8ff738ea961b2f5584bf7089afaa0a37b94910d18083bf649a7d395a41f04e68f14494d10ffc7d984a2c81e97f3421c1ec38c629b2456a3d8f3bf3915e86317ea71bb24422bef475e677e8967670b4f6ee2a80a45adcbd086a6537ab5fc12bf69f9072b620020de1880cec6cdea47543d1fec4c5ff547ac2447a1e210d9c128dc3337726eb63d5c1c731aa2c63ce175dbc8ebfb9c1e5198815be473781c3f82c2b59d23deb9739dda53c98d31a3fba57760aeaa89b0203010001'
);

INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* carol@strongswan.org */
  6, 1, X'30820122300d06092a864886f70d01010105000382010f003082010a0282010100b81b84920408e086c8d278d3ad2e9ffc01b89e8c423b612b908010f8174ff96f6729e84b185fb96e60783082c507ace9d64f79beb0252e05e5f1f7a89a0b33e6789f5deb665084cb230191c165bcad1a34563e011b349bb6ab517f01ecf7e2f4de961d36203b85e97811cb26b650cfd014d15dd2d2b71efd656e5638a24bf70986b8128bbae5f3b428d6360e03d3f4e816502e3d1d14d7165ab1a92a9fe15ef045d4e48ff5bd798ec80c9420962c9a9798b54a0ed2a00cf2c9651d7d9882e181c1ef6b1c43edcada2fd191e109962dbd26f38a00208c1ac3ed27a5924c60330c79878eb5c7a90960a6472f979aca9c5aee2bb4d0aed395b546c5e361910a06370203010001'
);

INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* dave@strongswan.org */
  6, 1, X'30820122300d06092a864886f70d01010105000382010f003082010a0282010100c66c299463a8a78abef5ffa45679b7a070b5139834b146aa5138d0f1d8845412e112e4429ceeab23473e395e8aa38b2c024118d85b7ddf504118eabedf9c793bd02c949d6799cabeefe03ff62e304ddec98313afd966bcf13f1fb1a619548a060e17fbede205225b574e679adc9f11bdf9e36b48bea058d360d62b8445f9524db98757a4d59865363c675d28667a5dfa967dd03eea23a2dbea32ab0e9a1f8bb885f5e12723113843a12dd00552fcd4f548b31174aab2610e4a8752f6fca95494584db65cc7bd1ef50ee0d8c8211efb5063a995801cc0c1a903042b7ff7c94094a0de5d7390a8f72a01949cd958c6f2012692bd5dba6f30b09c3c0b69622864450203010001'
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  1, 1
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  1, 5
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  2, 2
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  2, 6
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  3, 3
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  3, 7
);

/* Private Keys */

INSERT INTO private_keys (
   type, data
) VALUES ( /* key of CN=moon.strongswan.org' */
  1, X'308204a30201000282010100afae2e109ac0a71b437b6f1a9e5194d085c999fe2c8de11b261f016c88e734eb1a6767b15bc7d8338bf3acc14e8a18bf857fd3dfbce637e9b0d3654f15d9068bdf4450517cf72651be8d4c8ff738ea961b2f5584bf7089afaa0a37b94910d18083bf649a7d395a41f04e68f14494d10ffc7d984a2c81e97f3421c1ec38c629b2456a3d8f3bf3915e86317ea71bb24422bef475e677e8967670b4f6ee2a80a45adcbd086a6537ab5fc12bf69f9072b620020de1880cec6cdea47543d1fec4c5ff547ac2447a1e210d9c128dc3337726eb63d5c1c731aa2c63ce175dbc8ebfb9c1e5198815be473781c3f82c2b59d23deb9739dda53c98d31a3fba57760aeaa89b0203010001028201004080550d67a42036945a377ab072078f5fef9b0885573a34fb941ab3bcb816e7d2f3f050600049d2f3296e5e32f5e50c3c79a852d74a377127a915e329845b30f3b26342e7fcde26d92d8bd4b7d23fdf08f02217f129e2838a8ce1d4b78ce33eaa2095515b74b93cc87c216fa3dc77bdc4d86017ababaf0d3318c9d86f27e29aa3301f6d7990f6f7f71db9de23ac66800ba0db4f42bbe82932ca56e08ba730c63febaf2779198cee387ee0934b32a2610ab990a4b908951bb1db2345cf1905f11aeaa6d1b368b7f82b1345ad14544e11d47d6981fc4be083326050cb950363dad1b28dbc16db42ec0fa973312c7306063bc9f308a6b0bcc965e5cb7e0b323ca102818100e71fffd9c9a528bdcb6e9ad1a5f4b354e3ea337392784aac790b4fba7f46b3b58d55965573f6493b686375cf6a0c68da9379434b055b625f01d64a9f1934cb075b25db5ef568325039674d577590b5ec54284842e04c27c97103a151805c9b620a3df84181e3a0c10752a7da6cac9629471a2bc85b32c3a160f3a8adf2d783d302818100c2968f5baf0d246bb9671b1dcfadab3a23cd6f9f1cba8c4b0d9b09d6c30a24eec174f22a4d9d2818d760b79a61c9cdd1381487723a99773a629b58171a6e28706bf083700f35037a0cb0649c9359987ccf77b44b4b3d94c614c74537c7025b503dc9967095411ecaec4b4427bc39dd5dfccbb8bab5d92e9465ab11e5e05d7319028181008b306e388e837461b89dc786f256c7991c18f31b6ade1eba77bb242cc071a7d0726954bbe9b62cac26559fa165d04b6536e3146f9dae4733c83b717d1705003051e81e90b56226cac18740c0a7009b4ed3efde74c7f7950e6f8d2c1d951c30477ebb8b428822b9b105e3f54a49a0365e6d7f895683f5b273019c3bbd663dfc190281807f5def6e12b1a682407405a2c8ba2356c5f2853a7fa2778bf4d6e364c87b4e5b5d138023427438b7b1da63b35088b808570dd0ee6afee2b4bbb074c382905235ebe11d176f4cc2fed3696e21b2ad358b947d04ed37cd9220e99ed966be0383e38cddf373b3ae514a7fca704d15fe46306bf4a8f0c570e7f5486ae6273269d89902818031055903f23c7db8da8951aad134c83a7ca951c48c9a7b994f36d9815bc82c80527b6da8e4beff9fee67b1fde5064719a40448bd6d70d9da8910122402835a328e74cfd34e8b568c29fae6ff831ef824fc825e609547a06052a4113ec09f00649bb7b7d195a773f11711c88f152b10a1b4ae58bb6d8bfc176e39f96c7c0de5c8'
);

INSERT INTO private_key_identity (
  private_key, identity
) VALUES (
  1, 1
);

INSERT INTO private_key_identity (
  private_key, identity
) VALUES (
  1, 5
);

/* Configurations */

INSERT INTO ike_configs (
  local, remote
) VALUES (
  'PH_IP_MOON', '0.0.0.0'
);

INSERT INTO peer_configs (
  name, ike_cfg, local_id, remote_id
) VALUES (
  'rw', 1, 1, 4
);

INSERT INTO child_configs (
  name, updown
) VALUES (
  'rw', 'ipsec _updown iptables'
);

INSERT INTO peer_config_child_config (
  peer_cfg, child_cfg
) VALUES (
  1, 1
);

INSERT INTO traffic_selectors (
  type, start_addr, end_addr
) VALUES ( /* 10.1.0.0/16 */
  7, X'0a010000', X'0a01ffff'
);

INSERT INTO traffic_selectors (
  type
) VALUES ( /* dynamic/32 */
  7
);

INSERT INTO child_config_traffic_selector (
  child_cfg, traffic_selector, kind
) VALUES (
  1, 1, 0
);

INSERT INTO child_config_traffic_selector (
	child_cfg, traffic_selector, kind
) VALUES (
  1, 2, 3
);


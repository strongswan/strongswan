/* Identities */

INSERT INTO identities (
  type, data
) VALUES ( /* dave@strongswan.org */
  3, X'64617665407374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* moon.strongswan.org */
  2, X'6d6f6f6e2e7374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of dave@strongswan.org */
  11, X'de90b5d11c6c643c7450d36af8886ca31938fb72'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of moon.strongswan.org */
  11, X'e5e410876c2ac4bead854942a6de7658303a9fc1'
 );

/* Certificates */

INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* dave@strongswan.org */
  6, 1, X'30820122300d06092a864886f70d01010105000382010f003082010a0282010100c66c299463a8a78abef5ffa45679b7a070b5139834b146aa5138d0f1d8845412e112e4429ceeab23473e395e8aa38b2c024118d85b7ddf504118eabedf9c793bd02c949d6799cabeefe03ff62e304ddec98313afd966bcf13f1fb1a619548a060e17fbede205225b574e679adc9f11bdf9e36b48bea058d360d62b8445f9524db98757a4d59865363c675d28667a5dfa967dd03eea23a2dbea32ab0e9a1f8bb885f5e12723113843a12dd00552fcd4f548b31174aab2610e4a8752f6fca95494584db65cc7bd1ef50ee0d8c8211efb5063a995801cc0c1a903042b7ff7c94094a0de5d7390a8f72a01949cd958c6f2012692bd5dba6f30b09c3c0b69622864450203010001'
);

INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* moon.strongswan.org */
  6, 1, X'30820122300d06092a864886f70d01010105000382010f003082010a0282010100afae2e109ac0a71b437b6f1a9e5194d085c999fe2c8de11b261f016c88e734eb1a6767b15bc7d8338bf3acc14e8a18bf857fd3dfbce637e9b0d3654f15d9068bdf4450517cf72651be8d4c8ff738ea961b2f5584bf7089afaa0a37b94910d18083bf649a7d395a41f04e68f14494d10ffc7d984a2c81e97f3421c1ec38c629b2456a3d8f3bf3915e86317ea71bb24422bef475e677e8967670b4f6ee2a80a45adcbd086a6537ab5fc12bf69f9072b620020de1880cec6cdea47543d1fec4c5ff547ac2447a1e210d9c128dc3337726eb63d5c1c731aa2c63ce175dbc8ebfb9c1e5198815be473781c3f82c2b59d23deb9739dda53c98d31a3fba57760aeaa89b0203010001'
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  1, 1
);
$INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  1, 3
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  2, 2
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  2, 4
);

/* Private Keys */

INSERT INTO private_keys (
   type, data
) VALUES ( /* key of dave@strongswan.org */
  1, X'308204a40201000282010100c66c299463a8a78abef5ffa45679b7a070b5139834b146aa5138d0f1d8845412e112e4429ceeab23473e395e8aa38b2c024118d85b7ddf504118eabedf9c793bd02c949d6799cabeefe03ff62e304ddec98313afd966bcf13f1fb1a619548a060e17fbede205225b574e679adc9f11bdf9e36b48bea058d360d62b8445f9524db98757a4d59865363c675d28667a5dfa967dd03eea23a2dbea32ab0e9a1f8bb885f5e12723113843a12dd00552fcd4f548b31174aab2610e4a8752f6fca95494584db65cc7bd1ef50ee0d8c8211efb5063a995801cc0c1a903042b7ff7c94094a0de5d7390a8f72a01949cd958c6f2012692bd5dba6f30b09c3c0b696228644502030100010282010100903fb9caa2d8cd5454974a0e12bfd1fad5750e95ac58e462954194c4fcfed690130844e1186d7a04df9a20e2d62f26d20ba17f8a6a990b6bb0a788a0d2b7527b654fc38adaf2372eaffc7b036178c4639e63a84042f02993c8ac25ddf6b43ad34413b396b0a5c2e05c8c274db1ee025bf5fa9ad7fb9d5e75ed044606974835c7fbc39ae84b80acaae9e9624e6fe8ac0ca318ad8a7d1c6ed3a79261464e6ebdb9c02ef20cb1c206c58718d542ed9cb1428c5c3cebbd58dc25598bbdd9924c75fdfeac881949e5f10a7dd4dc25800bdb4bd479ca0bfb706f25847361b2d2565a412813273691b4a3a5a814dce52cdbe25d626e6c9e000ecd6a75cac275187e265102818100e596d3ee25cd98563b12bf718c0ce7e7a823ae8c84f1021552b6b0bf220b7e012861510ab49d612fe7ba05a202edf4927201af0f33f4137481811f884fc46723f94db8ed69b283376f3141ad7e6f0f52afee60e537111c5bd94642564981a822e54edb6797521fb5870c772993ff517ea9c24adcd9dc502f1364d26a3f05ec4f02818100dd3f81e8a4f463488db2b048f2ef208c1c98ee136636b6449cbd3424c93ab25916908823a1ef3a23b4798c77f92a3e29b9469f8014c6b862e23ab5fe6000f9552de01f72c0a1fcc731b0867a3bf1d27596fc9da6ecd74931ce120b1687d2a67b4e4fb32b7fb750b46645aa38ab011a4d5fedd53d20e5ae3a4a5551b6cc5f5d2b02818100ba744b9954ca2bb59c341596398f21a7593de13bed9b6d7db3b6fac3befa6652ba608e588b6664cf6afa00291b07f5601986948d5c3c14b0c19c03e7c82051433dec890b06941b4ca1d8f6e5d7908a7934b7fba92b9791d86614513b9266e20db4fcdde2bb59ceb6b5fec1a7dab1b7958e786424082a8c542f03ea7eaec038b1028180055e2312b7ddce02d69d3d35a7df3154f4e4a8f2038ad44539e0454197383b5779faabb2e19ce236378cb361bdc3ce9a488a74183168d8d45d54bb519e96a775ef94fe6e544a19cde360bb02802dcfc356946e66bc5c44c456918d7f507045e5bbf2a710291b13742cff07b03445e49377fe572c127e4009ddffcfe9b56fa2dd02818040d41f525d885c951dca35924f46e4e7f4e43f4ea2e670230deb674884f5b8599a368b1647dd87523c4fdb62661f6543edecc9ce48d4a7b8b2a29de21fd438a9cf4823b92c85180b390c4f8dfbc196628d349fed1edd32cba5c063e2739d2153d3677d4815e55b8b4e9d0989b32cf0060de2ded4cd59edf6a4364cb55aff9276'
);

INSERT INTO private_key_identity (
  private_key, identity
) VALUES (
  1, 1
);

INSERT INTO private_key_identity (
  private_key, identity
) VALUES (
  1, 3
);

/* Configurations */

INSERT INTO ike_configs (
  local, remote
) VALUES (
  'PH_IP_DAVE', 'PH_IP_MOON'
);

INSERT INTO peer_configs (
  name, ike_cfg, local_id, remote_id
) VALUES (
  'home', 1, 1, 2 
);

INSERT INTO child_configs (
  name, updown
) VALUES (
  'home', 'ipsec _updown iptables'
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
  1, 1, 1
);

INSERT INTO child_config_traffic_selector (
	child_cfg, traffic_selector, kind
) VALUES (
  1, 2, 2
);


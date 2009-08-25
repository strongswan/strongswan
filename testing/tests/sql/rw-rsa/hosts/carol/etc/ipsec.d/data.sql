/* Identities */

INSERT INTO identities (
  type, data
) VALUES ( /* carol@strongswan.org */
  3, X'6361726f6c407374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* moon.strongswan.org */
  2, X'6d6f6f6e2e7374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of carol@strongswan.org */
  11, X'5535eca6eba279baef887f18438fd227b16746d1'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* keyid of moon.strongswan.org */
  11, X'e5e410876c2ac4bead854942a6de7658303a9fc1'
 );

/* Certificates */

INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* carol@strongswan.org */
  6, 1, X'30820122300d06092a864886f70d01010105000382010f003082010a0282010100b81b84920408e086c8d278d3ad2e9ffc01b89e8c423b612b908010f8174ff96f6729e84b185fb96e60783082c507ace9d64f79beb0252e05e5f1f7a89a0b33e6789f5deb665084cb230191c165bcad1a34563e011b349bb6ab517f01ecf7e2f4de961d36203b85e97811cb26b650cfd014d15dd2d2b71efd656e5638a24bf70986b8128bbae5f3b428d6360e03d3f4e816502e3d1d14d7165ab1a92a9fe15ef045d4e48ff5bd798ec80c9420962c9a9798b54a0ed2a00cf2c9651d7d9882e181c1ef6b1c43edcada2fd191e109962dbd26f38a00208c1ac3ed27a5924c60330c79878eb5c7a90960a6472f979aca9c5aee2bb4d0aed395b546c5e361910a06370203010001'
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

INSERT INTO certificate_identity (
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
) VALUES ( /* key of carol@strongswan.org' */
  1, X'308204a30201000282010100b81b84920408e086c8d278d3ad2e9ffc01b89e8c423b612b908010f8174ff96f6729e84b185fb96e60783082c507ace9d64f79beb0252e05e5f1f7a89a0b33e6789f5deb665084cb230191c165bcad1a34563e011b349bb6ab517f01ecf7e2f4de961d36203b85e97811cb26b650cfd014d15dd2d2b71efd656e5638a24bf70986b8128bbae5f3b428d6360e03d3f4e816502e3d1d14d7165ab1a92a9fe15ef045d4e48ff5bd798ec80c9420962c9a9798b54a0ed2a00cf2c9651d7d9882e181c1ef6b1c43edcada2fd191e109962dbd26f38a00208c1ac3ed27a5924c60330c79878eb5c7a90960a6472f979aca9c5aee2bb4d0aed395b546c5e361910a063702030100010282010100a7870abc1f85c061858dd7baae24f61947abaa41f0e6bd85f9c83f28b175e980d0bc168f76cf6c199f18def3afbc4b40c0edb2d7accb3834cfc7bd57234d3c5de4b707ac737ea3478144255079761581f9cbdc41ff72809ad90ba069ad2ae7cf7057e29ee4f7a4e40c890c75de826c8768da16e9072af0bd1db6282902ade34cb1b9c3fdd00a8f0330328e18d477009ac5a43952fe05b7257b8b4e7f8f5288e858ef56ea3a031980d38b879e6327d949a8f3c19bf379c1297b3defc0a374a6ea6f1c0e8124247c33392ae446081f486f58bb41cbcba25915d37eefe0828408f7f679841588424ef59b6dee30805b926fa80e7ff57cb4817167ca72bf51c8cf9102818100da567b0cbbc426e4455ffdd1b8013644d9f47785b05b163a0155c81d57c0cd84fe73aa75125caf116de50b7adc369707ed91127db7d4422bb08cff5ddf91f4a0e5fb264e098fe6fe62f8a2ab933eeac41893f365d8165f79143855b5a5b7dc31c9b34a9d453ee7c8d7b24f89e3ed51bfeadc2e1102308a967b241dfb44c8ad6902818100d7dd78437c533a15fd1dd6b0634334e79c31d215017f5a8869e42cbada3fb09167585e087e72f91575441f7cca9a64246df57f0e45f1ae86a289a4307586aa1cc3cd069c65057cc3b0baac3634064e53179bde9af2531a5af2770a1d7ccbdc263f18299ad2ec0d224b718002633a546af74c7cac72ccdf253ab4370137bf829f02818063b2f5c15cc43716296fa9d167fa75b37eeb18e0dd24dac365f4abca6a55ca031ec5e6624b1e337afbf9890273282253267206458df9c8b5768b0bd8ebcc142e9c95d069f607d5ecf7789d9f473f85a841a8dd8df5dc518052715f01f14841ae22725271fa3abd5082de135fddca7277f660d05047f5ae73048bfb7ccf6deb7102818028b2b4ade48ebc70d0dc03521624e1a0992e3b71826ac462dbb40d4add430cc31d3ce7ddaa197b24b48b37748bae381b363006d8660f7edc1b60dff7d2f0a4b9efa0841290694c7088ad69327ef48167e1179e0c908b6278ab260e5e28dd36906f6cdacb39e10f48dbf8762dfd0f4e432c84db2c98285019f0cb7163656351f902818042a7d7d7f9416b3f3b50cf5815dfbc249cd3572e494c76d1ae99dc1e8bc63fbb32e5c18d5c4f90681e9046999cdcf0826f904350b9d67227f606382d9c7b3b1332d22744b2cefa691ab82dbec8e976a406b0902d0f4889392f80d39e2581ac42feed9085964650485e34811b04fa1f34c47cde5cbdd1d20f30111851a3c187ca'
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
  'PH_IP_CAROL', 'PH_IP_MOON'
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


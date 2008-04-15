DROP TABLE IF EXISTS identities;
CREATE TABLE identities (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  data BLOB NOT NULL,
  UNIQUE (type, data)
);

DROP TABLE IF EXISTS child_configs;
CREATE TABLE child_configs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  lifetime INTEGER NOT NULL DEFAULT '1200',
  rekeytime INTEGER NOT NULL DEFAULT '1020',
  jitter INTEGER NOT NULL DEFAULT '180',
  updown TEXT DEFAULT NULL,
  hostaccess INTEGER NOT NULL DEFAULT '0',
  mode INTEGER NOT NULL DEFAULT '1',
  dpd_action INTEGER NOT NULL DEFAULT '0',
  close_action INTEGER NOT NULL DEFAULT '0'
);
DROP INDEX IF EXISTS child_configs_name;
CREATE INDEX child_configs_name ON child_configs (
  name
);

DROP TABLE IF EXISTS child_config_traffic_selector;
CREATE TABLE child_config_traffic_selector (
  child_cfg INTEGER NOT NULL,
  traffic_selector INTEGER NOT NULL,
  kind INTEGER NOT NULL
);
DROP INDEX IF EXISTS child_config_traffic_selector;
CREATE INDEX child_config_traffic_selector_all ON child_config_traffic_selector (
  child_cfg, traffic_selector
);

DROP TABLE IF EXISTS ike_configs;
CREATE TABLE ike_configs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  certreq INTEGER NOT NULL DEFAULT '1',
  force_encap INTEGER NOT NULL DEFAULT '0',
  local TEXT NOT NULL,
  remote TEXT NOT NULL
);

DROP TABLE IF EXISTS peer_configs;
CREATE TABLE peer_configs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  ike_version INTEGER NOT NULL DEFAULT '2',
  ike_cfg INTEGER NOT NULL,
  local_id TEXT NOT NULL,
  remote_id TEXT NOT NULL,
  cert_policy INTEGER NOT NULL DEFAULT '1',
  uniqueid INTEGER NOT NULL DEFAULT '0',
  auth_method INTEGER NOT NULL DEFAULT '1',
  eap_type INTEGER NOT NULL DEFAULT '0',
  eap_vendor INTEGER NOT NULL DEFAULT '0',
  keyingtries INTEGER NOT NULL DEFAULT '1',
  rekeytime INTEGER NOT NULL DEFAULT '0',
  reauthtime INTEGER NOT NULL DEFAULT '3600',
  jitter INTEGER NOT NULL DEFAULT '180',
  overtime INTEGER NOT NULL DEFAULT '300',
  mobike INTEGER NOT NULL DEFAULT '1',
  dpd_delay INTEGER NOT NULL DEFAULT '120',
  virtual TEXT DEFAULT NULL,
  pool TEXT DEFAULT NULL,
  mediation INTEGER NOT NULL DEFAULT '0',
  mediated_by INTEGER NOT NULL DEFAULT '0',
  peer_id INTEGER NOT NULL DEFAULT '0'
);
DROP INDEX IF EXISTS peer_configs_name;
CREATE INDEX peer_configs_name ON peer_configs (
  name
);

DROP TABLE IF EXISTS peer_config_child_config;
CREATE TABLE peer_config_child_config (
  peer_cfg INTEGER NOT NULL,
  child_cfg INTEGER NOT NULL,
  PRIMARY KEY (peer_cfg, child_cfg)
);

DROP TABLE IF EXISTS traffic_selectors;
CREATE TABLE traffic_selectors (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL DEFAULT '7',
  protocol INTEGER NOT NULL DEFAULT '0',
  start_addr BLOB DEFAULT NULL,
  end_addr BLOB DEFAULT NULL,
  start_port INTEGER NOT NULL DEFAULT '0',
  end_port INTEGER NOT NULL DEFAULT '65535'
);

DROP TABLE IF EXISTS certificates;
CREATE TABLE certificates (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  keytype INTEGER NOT NULL,
  data BLOB NOT NULL
);

DROP TABLE IF EXISTS certificate_identity;
CREATE TABLE certificate_identity (
  certificate INTEGER NOT NULL,
  identity INTEGER NOT NULL,
  PRIMARY KEY (certificate, identity)
);

DROP TABLE IF EXISTS private_keys;
CREATE TABLE private_keys (
  id INTEGER NOT NULL  PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  data BLOB NOT NULL
);

DROP TABLE IF EXISTS private_key_identity;
CREATE TABLE private_key_identity (
  private_key INTEGER NOT NULL,
  identity INTEGER NOT NULL,
  PRIMARY KEY (private_key, identity)
);

DROP TABLE IF EXISTS shared_secrets;
CREATE TABLE shared_secrets (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  data BLOB NOT NULL
);

DROP TABLE IF EXISTS shared_secret_identity;
CREATE TABLE shared_secret_identity (
  shared_secret INTEGER NOT NULL,
  identity INTEGER NOT NULL,
  PRIMARY KEY (shared_secret, identity)
);

DROP TABLE IF EXISTS ike_sas;
CREATE TABLE ike_sas (
  local_spi BLOB NOT NULL PRIMARY KEY,
  remote_spi BLOB NOT NULL,
  id INTEGER NOT NULL,
  initiator INTEGER NOT NULL,
  local_id_type INTEGER NOT NULL,
  local_id_data BLOB NOT NULL,
  remote_id_type INTEGER NOT NULL,
  remote_id_data BLOB NOT NULL,
  host_family INTEGER NOT NULL,
  local_host_data BLOB NOT NULL,
  remote_host_data BLOB NOT NULL,
  created INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS logs;
CREATE TABLE logs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  local_spi BLOB NOT NULL,
  signal INTEGER NOT NULL,
  level INTEGER NOT NULL,
  msg TEXT NOT NULL,
  time INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP
);

/* Identities */

INSERT INTO identities (
  type, data
) VALUES ( /* moon.strongswan.org */
  2, X'6d6f6f6e2e7374726f6e677377616e2e6f7267'
 );

INSERT INTO identities (
  type, data
) VALUES ( /* sun.strongswan.org */
  2, X'73756e2e7374726f6e677377616e2e6f7267'
 );

/* Shared Secrets */

INSERT INTO shared_secrets (
   type, data
) VALUES ( 
  1, X'bfe364c58f4b2d9bf08f8a820b6a3f806ad60c5d9ddb58cb'
);

INSERT INTO shared_secret_identity (
  shared_secret, identity
) VALUES (
  1, 1
);

INSERT INTO shared_secret_identity (
  shared_secret, identity
) VALUES (
  1, 2
);

/* Configurations */

INSERT INTO ike_configs (
  local, remote
) VALUES (
  'PH_IP_SUN', 'PH_IP_MOON'
);

INSERT INTO peer_configs (
  name, ike_cfg, local_id, remote_id, auth_method, mobike
) VALUES (
  'net-net', 1, 2, 1, 2, 0
);

INSERT INTO child_configs (
  name, updown
) VALUES (
  'net-net', 'ipsec _updown iptables'
);

INSERT INTO peer_config_child_config (
  peer_cfg, child_cfg
) VALUES (
  1, 1
);

INSERT INTO traffic_selectors (
  type, start_addr, end_addr
) VALUES (
  7, X'0a010000', X'0a01ffff'
);

INSERT INTO traffic_selectors (
  type, start_addr, end_addr
) VALUES (
  7, X'0a020000', X'0a02ffff'
);

INSERT INTO child_config_traffic_selector (
  child_cfg, traffic_selector, kind
) VALUES (
  1, 2, 0
);

INSERT INTO child_config_traffic_selector (
	child_cfg, traffic_selector, kind
) VALUES (
  1, 1, 1
);


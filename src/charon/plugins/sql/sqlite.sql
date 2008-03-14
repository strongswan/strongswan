
DROP TABLE IF EXISTS child_configs;
CREATE TABLE child_configs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  lifetime INTEGER NOT NULL default '1500',
  rekeytime INTEGER NOT NULL default '1200',
  jitter INTEGER NOT NULL default '60',
  updown TEXT default NULL,
  hostaccess INTEGER NOT NULL default '1',
  mode INTEGER NOT NULL default '1'
);


DROP TABLE IF EXISTS child_config_traffic_selector;
CREATE TABLE child_config_traffic_selector (
  child_cfg INTEGER NOT NULL,
  traffic_selector INTEGER NOT NULL,
  kind INTEGER NOT NULL
);


DROP TABLE IF EXISTS ike_configs;
CREATE TABLE ike_configs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  certreq INTEGER NOT NULL default '1',
  force_encap INTEGER NOT NULL default '0',
  local TEXT NOT NULL,
  remote TEXT NOT NULL
);

DROP TABLE IF EXISTS peer_configs;
CREATE TABLE peer_configs (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  ike_version INTEGER NOT NULL default '2',
  ike_cfg INTEGER NOT NULL,
  local_id TEXT NOT NULL,
  remote_id TEXT NOT NULL,
  cert_policy INTEGER NOT NULL default '1',
  auth_method INTEGER NOT NULL default '1',
  eap_type INTEGER NOT NULL default '0',
  eap_vendor INTEGER NOT NULL default '0',
  keyingtries INTEGER NOT NULL default '3',
  rekeytime INTEGER NOT NULL default '7200',
  reauthtime INTEGER NOT NULL default '0',
  jitter INTEGER NOT NULL default '180',
  overtime INTEGER NOT NULL default '300',
  mobike INTEGER NOT NULL default '1',
  dpd_delay INTEGER NOT NULL default '120',
  dpd_action INTEGER NOT NULL default '1',
  local_vip TEXT default NULL,
  remote_vip TEXT default NULL,
  mediation INTEGER NOT NULL default '0',
  mediated_by INTEGER NOT NULL default '0',
  peer_id TEXT default NULL
);

DROP TABLE IF EXISTS peer_config_child_config;
CREATE TABLE peer_config_child_config (
  peer_cfg INTEGER NOT NULL,
  child_cfg INTEGER NOT NULL
);

DROP TABLE IF EXISTS traffic_selectors;
CREATE TABLE traffic_selectors (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL default '7',
  protocol INTEGER NOT NULL default '0',
  start_addr TEXT default NULL,
  end_addr TEXT default NULL,
  start_port INTEGER NOT NULL default '0',
  end_port INTEGER NOT NULL default '65535'
);

DROP TABLE IF EXISTS shared_secrets;
CREATE TABLE shared_secrets (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	type INTEGER NOT NULL,
	local TEXT default NULL,
	remote TEXT default NULL,
	data BLOB NOT NULL
);

DROP TABLE IF EXISTS certificates;
CREATE TABLE certificates (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	type INTEGER NOT NULL,
	keytype INTEGER NOT NULL,
	keyid BLOB NOT NULL,
	subject TEXT default NULL,
	data BLOB NOT NULL
);

DROP TABLE IF EXISTS private_keys;
CREATE TABLE private_keys (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	type INTEGER NOT NULL,
	keyid BLOB NOT NULL,
	data BLOB NOT NULL
);

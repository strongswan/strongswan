

DROP TABLE IF EXISTS `child_configs`;
CREATE TABLE `child_configs` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `name` varchar(32) collate utf8_unicode_ci NOT NULL,
  `lifetime` mediumint(8) unsigned NOT NULL default '1500',
  `rekeytime` mediumint(8) unsigned NOT NULL default '1200',
  `jitter` mediumint(8) unsigned NOT NULL default '60',
  `updown` varchar(128) collate utf8_unicode_ci default NULL,
  `hostaccess` tinyint(1) unsigned NOT NULL default '1',
  `mode` tinyint(4) unsigned NOT NULL default '1',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `child_config_traffic_selector`;
CREATE TABLE `child_config_traffic_selector` (
  `child_cfg` int(10) unsigned NOT NULL,
  `traffic_selector` int(10) unsigned NOT NULL,
  `kind` tinyint(3) unsigned NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `ike_configs`;
CREATE TABLE `ike_configs` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `certreq` tinyint(3) unsigned NOT NULL default '1',
  `force_encap` tinyint(1) NOT NULL default '0',
  `local` varchar(64) collate utf8_unicode_ci NOT NULL,
  `remote` varchar(64) collate utf8_unicode_ci NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `peer_configs`;
CREATE TABLE `peer_configs` (
  `id` int(11) NOT NULL auto_increment,
  `name` varchar(32) collate utf8_unicode_ci NOT NULL,
  `ike_version` tinyint(3) unsigned NOT NULL default '2',
  `ike_cfg` int(10) unsigned NOT NULL,
  `local_id` varchar(64) collate utf8_unicode_ci NOT NULL,
  `remote_id` varchar(64) collate utf8_unicode_ci NOT NULL,
  `cert_policy` tinyint(3) unsigned NOT NULL default '1',
  `auth_method` tinyint(3) unsigned NOT NULL default '1',
  `eap_type` tinyint(3) unsigned NOT NULL default '0',
  `eap_vendor` smallint(5) unsigned NOT NULL default '0',
  `keyingtries` tinyint(3) unsigned NOT NULL default '3',
  `rekeytime` mediumint(8) unsigned NOT NULL default '7200',
  `reauthtime` mediumint(8) unsigned NOT NULL default '0',
  `jitter` mediumint(8) unsigned NOT NULL default '180',
  `overtime` mediumint(8) unsigned NOT NULL default '300',
  `mobike` tinyint(1) NOT NULL default '1',
  `dpd_delay` mediumint(8) unsigned NOT NULL default '120',
  `dpd_action` tinyint(3) unsigned NOT NULL default '1',
  `local_vip` varchar(128) collate utf8_unicode_ci default NULL,
  `remote_vip` varchar(128) collate utf8_unicode_ci default NULL,
  `mediation` tinyint(1) NOT NULL default '0',
  `mediated_by` int(11) NOT NULL default '0',
  `peer_id` varchar(64) collate utf8_unicode_ci default NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `peer_config_child_config`;
CREATE TABLE `peer_config_child_config` (
  `peer_cfg` int(10) unsigned NOT NULL,
  `child_cfg` int(10) unsigned NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `traffic_selectors`;
CREATE TABLE `traffic_selectors` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `type` tinyint(3) unsigned NOT NULL default '7',
  `protocol` smallint(5) unsigned NOT NULL default '0',
  `start_addr` varchar(40) collate utf8_unicode_ci default NULL,
  `end_addr` varchar(40) collate utf8_unicode_ci default NULL,
  `start_port` smallint(5) unsigned NOT NULL default '0',
  `end_port` smallint(5) unsigned NOT NULL default '65535',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS shared_secrets;
CREATE TABLE shared_secrets (
  `id` int(10) unsigned NOT NULL auto_increment,
  `type` tinyint(3) unsigned NOT NULL,
  `local` varchar(64) default NULL,
  `remote` varchar(64) default NULL,
  `data` BLOB NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS certificates;
CREATE TABLE certificates (
  `id` int(10) unsigned NOT NULL auto_increment,
  `type` tinyint(3) unsigned NOT NULL,
  `keytype` tinyint(3) unsigned NOT NULL,
  `keyid` BLOB NOT NULL,
  `subject` varchar(64) default NULL,
  `data` BLOB NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS private_keys;
CREATE TABLE private_keys (
  `id` int(10) unsigned NOT NULL auto_increment,
  `type` tinyint(3) unsigned NOT NULL,
  `keyid` tinyblob NOT NULL,
  `data` BLOB NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


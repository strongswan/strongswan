
CREATE TABLE IF NOT EXISTS `Peer` (
  `IdPeer` int(10) unsigned NOT NULL auto_increment,
  `IdUser` int(10) unsigned NOT NULL,
  `Alias` varchar(30) collate utf8_unicode_ci NOT NULL,
  `KeyId` varbinary(20) NOT NULL,
  `PublicKey` blob NOT NULL,
  PRIMARY KEY  (`IdPeer`),
  KEY `KeyId` (`KeyId`),
  KEY `IdUser` (`IdUser`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


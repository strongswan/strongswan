/* PTS SQLite database */

DROP TABLE IF EXISTS files;
CREATE TABLE files (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  path TEXT NOT NULL
);
DROP INDEX IF EXISTS files_path;
CREATE INDEX files_path ON files (
  path
);

DROP TABLE IF EXISTS products;
CREATE TABLE products (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);
DROP INDEX IF EXISTS products_name;
CREATE INDEX products_name ON products (
  name
);

DROP TABLE IF EXISTS product_file;
CREATE TABLE product_file (
  product INTEGER NOT NULL,
  file INTEGER NOT NULL,
  measurement INTEGER DEFAULT 0,
  metadata INTEGER DEFAULT 0,
  PRIMARY KEY (product, file)
);

DROP TABLE IF EXISTS file_hashes;
CREATE TABLE file_hashes (
  file INTEGER NOT NULL,
  directory INTEGER DEFAULT 0,
  product INTEGER NOT NULL,
  key INTEGER DEFAULT 0,
  algo INTEGER NOT NULL,
  hash BLOB NOT NULL,
  PRIMARY KEY(file, directory, product, algo)
);

DROP TABLE IF EXISTS keys;
CREATE TABLE keys (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  keyid BLOB NOT NULL,
  owner TEXT NOT NULL
);
DROP INDEX IF EXISTS keys_keyid;
CREATE INDEX keys_keyid ON keys (
  keyid
);
DROP INDEX IF EXISTS keys_owner;
CREATE INDEX keys_owner ON keys (
  owner
);

DROP TABLE IF EXISTS components;
CREATE TABLE components (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  vendor_id INTEGER NOT NULL,
  name INTEGER NOT NULL,
  qualifier INTEGER DEFAULT 0
);


DROP TABLE IF EXISTS key_component;
CREATE TABLE key_component (
  key INTEGER NOT NULL,
  component INTEGER NOT NULL,
  depth INTEGER DEFAULT 0,
  seq_no INTEGER DEFAULT 0,
  PRIMARY KEY (key, component)
);


DROP TABLE IF EXISTS component_hashes;
CREATE TABLE component_hashes (
  component INTEGER NOT NULL,
  key INTEGER NOT NULL,
  seq_no INTEGER NOT NULL,
  pcr INTEGER NOT NULL,
  algo INTEGER NOT NULL,
  hash BLOB NOT NULL,
  PRIMARY KEY(component, key, seq_no, algo)
);

DROP TABLE IF EXISTS packages;
CREATE TABLE packages (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);
DROP INDEX IF EXISTS packages_name;
CREATE INDEX packages_name ON packages (
  name
);

DROP TABLE IF EXISTS versions;
CREATE TABLE versions (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  package INTEGER NOT NULL,
  product INTEGER NOT NULL,
  release TEXT NOT NULL,
  security INTEGER DEFAULT 0,
  time INTEGER DEFAULT 0
);
DROP INDEX IF EXISTS versions_release;
CREATE INDEX versions_release ON versions (
  release
);
DROP INDEX IF EXISTS versions_package_product;
CREATE INDEX versions_package_product ON versions (
  package, product
);

DROP TABLE IF EXISTS devices;
CREATE TABLE devices (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  value BLOB NOT NULL
);
DROP INDEX IF EXISTS devices_id;
CREATE INDEX devices_value ON devices (
  value
);

DROP TABLE IF EXISTS device_infos;
CREATE TABLE device_infos (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  device INTEGER NOT NULL,
  time INTEGER NOT NULL,
  ar_id INTEGER DEFAULT 0,
  product INTEGER DEFAULT 0,
  count INTEGER DEFAULT 0,
  count_update INTEGER DEFAULT 0,
  count_blacklist INTEGER DEFAULT 0,
  flags INTEGER DEFAULT 0
);

DROP TABLE IF EXISTS identities;
CREATE TABLE identities (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  data BLOB NOT NULL,
  UNIQUE (type, data)
);

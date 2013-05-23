/* IMV PTS SQLite database */

DROP TABLE IF EXISTS directories;
CREATE TABLE directories (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL
);
DROP INDEX IF EXISTS directories_path;
CREATE INDEX directories_path ON directories (
  path
);

DROP TABLE IF EXISTS files;
CREATE TABLE files (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  dir INTEGER DEFAULT 0 REFERENCES directories(id),
  name TEXT NOT NULL
);
DROP INDEX IF EXISTS files_name;
CREATE INDEX files_name ON files (
  name
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

DROP TABLE IF EXISTS algorithms;
CREATE TABLE algorithms (
  id INTEGER PRIMARY KEY,
  name VARCHAR(20) not NULL
);

DROP TABLE IF EXISTS file_hashes;
CREATE TABLE file_hashes (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  file INTEGER NOT NULL REFERENCES files(id),
  product INTEGER NOT NULL REFERENCES products(id),
  device INTEGER DEFAULT 0,
  algo INTEGER NOT NULL REFERENCES algorithms(id),
  hash BLOB NOT NULL
);

DROP TABLE IF EXISTS groups;
CREATE TABLE groups (
  id integer NOT NULL PRIMARY KEY,
  name varchar(50) NOT NULL UNIQUE
);

DROP TABLE IF EXISTS group_members;
CREATE TABLE group_members (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  group_id integer NOT NULL REFERENCES groups(id),
  device integer NOT NULL REFERENCES devices(id),
  UNIQUE (group_id, device)
);

DROP TABLE IF EXISTS default_product_groups;
CREATE TABLE default_product_groups (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  group_id integer NOT NULL REFERENCES groups(id),
  product integer NOT NULL REFERENCES products(id),
  UNIQUE (group_id, product)
);

DROP TABLE IF EXISTS policies;
CREATE TABLE policies (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  type integer NOT NULL,
  name varchar(100) NOT NULL UNIQUE,
  argument text DEFAULT '' NOT NULL,
  rec_fail integer NOT NULL,
  rec_noresult integer NOT NULL,
  file integer DEFAULT 0 REFERENCES files(id),
  dir integer DEFAULT 0 REFERENCES directories(id)
);

DROP TABLE IF EXISTS enforcements;
CREATE TABLE enforcements (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  policy integer NOT NULL REFERENCES policies(id),
  group_id integer NOT NULL REFERENCES groups(id),
  max_age integer NOT NULL,
  UNIQUE (policy, group_id)
);

DROP TABLE IF EXISTS sessions;
CREATE TABLE sessions (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  time INTEGER NOT NULL,
  connection INTEGER NOT NULL,
  identity INTEGER DEFAULT 0 REFERENCES identities(id),
  device INTEGER DEFAULT 0 REFERENCES devices(id),
  product INTEGER DEFAULT 0 REFERENCES products(id),
  rec INTEGER DEFAULT 3
);

DROP TABLE IF EXISTS workitems;
CREATE TABLE workitems (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  session integer NOT NULL REFERENCES sessions(id),
  enforcement integer NOT NULL REFERENCES enforcements(id),
  type integer NOT NULL,
  argument text NOT NULL,
  rec_fail integer NOT NULL,
  rec_noresult integer NOT NULL,
  rec_final integer DEFAULT 3,
  result text
);
DROP INDEX IF EXISTS workitems_session;
CREATE INDEX workitems_sessions ON workitems (
  session
);

DROP TABLE IF EXISTS results;
CREATE TABLE results (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  session integer NOT NULL REFERENCES measurements(id),
  policy integer NOT NULL REFERENCES policies(id),
  rec integer NOT NULL,
  result text NOT NULL
);
DROP INDEX IF EXISTS results_session;
CREATE INDEX results_session ON results (
  session
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

DROP TABLE IF EXISTS identities;
CREATE TABLE identities (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  value BLOB NOT NULL,
  UNIQUE (type, value)
);


/* PTS SQLite database */

DROP TABLE IF EXISTS files;
CREATE TABLE files (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  type INTEGER NOT NULL,
  path TEXT NOT NULL,
  measurement INTEGER DEFAULT 0,
  metadata INTEGER DEFAULT 0
);

DROP TABLE IF EXISTS components;
CREATE TABLE components (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  vendor_id INTEGER NOT NULL,
  name INTEGER NOT NULL,
  qualifier INTEGER DEFAULT 0
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
  PRIMARY KEY (product, file)
);

DROP TABLE IF EXISTS product_component;
CREATE TABLE product_component (
  product INTEGER NOT NULL,
  component INTEGER NOT NULL,
  sequence INTEGER DEFAULT 0,
  PRIMARY KEY (product, component)
);

DROP TABLE IF EXISTS file_hashes;
CREATE TABLE file_hashes (
  file INTEGER NOT NULL,
  directory INTEGER DEFAULT 0,
  product INTEGER NOT NULL,
  algo INTEGER NOT NULL,
  hash BLOB NOT NULL,
  PRIMARY KEY(file, directory, product, algo)
);


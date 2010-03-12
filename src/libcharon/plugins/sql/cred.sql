
DROP TABLE IF EXISTS shared_secrets;
CREATE TABLE shared_secrets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type INTEGER,
	local TEXT, 
	remote TEXT
);

DROP TABLE IF EXISTS certificates;
CREATE TABLE certificates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type INTEGER,
	subject TEXT,
	data BLOB,
);

DROP TABLE IF EXISTS private_keys;
CREATE TABLE private_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type INTEGER,
	keyid BLOB,
	data BLOB,
);

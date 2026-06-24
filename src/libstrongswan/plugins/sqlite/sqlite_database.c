/*
 * Copyright (C) 2013-2026 Tobias Brunner
 * Copyright (C) 2007 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "sqlite_database.h"

#include <sqlite3.h>
#include <unistd.h>
#include <library.h>
#include <utils/debug.h>
#include <threading/mutex.h>
#include <threading/thread_value.h>

typedef struct private_sqlite_database_t private_sqlite_database_t;

/**
 * Private data of sqlite_database
 */
struct private_sqlite_database_t {

	/**
	 * Public interface
	 */
	sqlite_database_t public;

	/**
	 * Path to the database file
	 */
	char *file;

	/**
	 * Connection pool, contains conn_t
	 */
	linked_list_t *pool;

	/**
	 * Mutex used to lock connection pool
	 */
	mutex_t *mutex;

	/**
	 * Thread-specific connection, as conn_t
	 */
	thread_value_t *conn;
};

/**
 * Connection entry
 */
typedef struct {

	/**
	 * SQLite database connection
	 */
	sqlite3 *db;

	/**
	 * Refcounter if queries are recursive or transaction() is called
	 * multiple times
	 */
	refcount_t refs;

	/**
	 * Transaction state on the connection
	 */
	enum {
		/* no transaction is currently active */
		TRANSACTION_NONE,
		/* a transaction is currently active */
		TRANSACTION_ACTIVE,
		/* rollback was called for at least one nested transaction */
		TRANSACTION_ROLLBACK,
	} transaction;

} conn_t;

/**
 * Release a database connection
 */
static void conn_release(private_sqlite_database_t *this, conn_t *conn)
{
	if (ref_put(&conn->refs))
	{
		this->conn->set(this->conn, NULL);
	}
}

/**
 * Destroy a database connection
 */
static void conn_destroy(conn_t *this)
{
	if (sqlite3_close(this->db) == SQLITE_BUSY)
	{
		DBG1(DBG_LIB, "closing SQLite connection failed: database busy");
	}
	free(this);
}

/**
 * Busy handler implementation
 */
CALLBACK(busy_handler, int,
	private_sqlite_database_t *this, int count)
{
	/* add a backoff time, quadratically increasing with every try */
	usleep(count * count * 1000);
	/* always retry */
	return 1;
}

/**
 * Acquire/Reuse a database connection
 */
static conn_t *conn_get(private_sqlite_database_t *this)
{
	conn_t *current, *found = NULL;
	enumerator_t *enumerator;

	current = this->conn->get(this->conn);
	if (current)
	{
		ref_get(&current->refs);
		return current;
	}

	this->mutex->lock(this->mutex);
	enumerator = this->pool->create_enumerator(this->pool);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (!ref_cur(&current->refs))
		{
			found = current;
			ref_get(&found->refs);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (!found)
	{
		INIT(found,
			.refs = 1,
		);

		if (sqlite3_open(this->file, &found->db) != SQLITE_OK)
		{
			DBG1(DBG_LIB, "opening SQLite database '%s' failed: %s",
				 this->file, sqlite3_errmsg(found->db));
			conn_destroy(found);
			return NULL;
		}
		sqlite3_busy_handler(found->db, busy_handler, this);

		this->mutex->lock(this->mutex);
		this->pool->insert_last(this->pool, found);
		DBG2(DBG_LIB, "increased SQLite connection pool size to %d",
			 this->pool->get_count(this->pool));
		this->mutex->unlock(this->mutex);
	}
	this->conn->set(this->conn, found);
	return found;
}

/**
 * Create and run an SQLite prepared statement using the given SQL string and
 * arguments
 */
static sqlite3_stmt* run(sqlite3 *db, char *sql, va_list *args)
{
	sqlite3_stmt *stmt = NULL;
	int params, i, res = SQLITE_OK;

#ifdef HAVE_SQLITE3_PREPARE_V2
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK)
#else
	if (sqlite3_prepare(db, sql, -1, &stmt, NULL) == SQLITE_OK)
#endif
	{
		params = sqlite3_bind_parameter_count(stmt);
		for (i = 1; i <= params; i++)
		{
			switch (va_arg(*args, db_type_t))
			{
				case DB_INT:
				{
					res = sqlite3_bind_int(stmt, i, va_arg(*args, int));
					break;
				}
				case DB_UINT:
				{
					res = sqlite3_bind_int64(stmt, i, va_arg(*args, u_int));
					break;
				}
				case DB_TEXT:
				{
					const char *text = va_arg(*args, const char*);
					res = sqlite3_bind_text(stmt, i, text, -1,
											SQLITE_TRANSIENT);
					break;
				}
				case DB_BLOB:
				{
					chunk_t c = va_arg(*args, chunk_t);
					res = sqlite3_bind_blob(stmt, i, c.ptr, c.len,
											SQLITE_TRANSIENT);
					break;
				}
				case DB_DOUBLE:
				{
					res = sqlite3_bind_double(stmt, i, va_arg(*args, double));
					break;
				}
				case DB_NULL:
				{
					res = sqlite3_bind_null(stmt, i);
					break;
				}
				default:
				{
					res = SQLITE_MISUSE;
					break;
				}
			}
			if (res != SQLITE_OK)
			{
				break;
			}
		}
	}
	else
	{
		DBG1(DBG_LIB, "preparing sqlite statement failed: %s",
			 sqlite3_errmsg(db));
	}
	if (res != SQLITE_OK)
	{
		DBG1(DBG_LIB, "binding sqlite statement failed: %s",
			 sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return NULL;
	}
	return stmt;
}

typedef struct {
	/** Public interface */
	enumerator_t public;
	/** Assigned database connection */
	conn_t *conn;
	/** Associated SQLite statement */
	sqlite3_stmt *stmt;
	/** Number of result columns */
	int count;
	/** Column types */
	db_type_t *columns;
	/** Back-reference to parent */
	private_sqlite_database_t *database;
} sqlite_enumerator_t;

METHOD(enumerator_t, sqlite_enumerator_destroy, void,
	sqlite_enumerator_t *this)
{
	sqlite3_finalize(this->stmt);
	conn_release(this->database, this->conn);
	free(this->columns);
	free(this);
}

METHOD(enumerator_t, sqlite_enumerator_enumerate, bool,
	sqlite_enumerator_t *this, va_list args)
{
	int i;

	switch (sqlite3_step(this->stmt))
	{
		case SQLITE_ROW:
			break;
		default:
			DBG1(DBG_LIB, "stepping SQLite statement failed: %s",
				 sqlite3_errmsg(this->conn->db));
			/* fall */
		case SQLITE_DONE:
			return FALSE;
	}

	for (i = 0; i < this->count; i++)
	{
		switch (this->columns[i])
		{
			case DB_INT:
			{
				int *value = va_arg(args, int*);
				*value = sqlite3_column_int(this->stmt, i);
				break;
			}
			case DB_UINT:
			{
				u_int *value = va_arg(args, u_int*);
				*value = (u_int)sqlite3_column_int64(this->stmt, i);
				break;
			}
			case DB_TEXT:
			{
				const unsigned char **value = va_arg(args, const unsigned char**);
				*value = sqlite3_column_text(this->stmt, i);
				break;
			}
			case DB_BLOB:
			{
				chunk_t *chunk = va_arg(args, chunk_t*);
				chunk->len = sqlite3_column_bytes(this->stmt, i);
				chunk->ptr = (u_char*)sqlite3_column_blob(this->stmt, i);
				break;
			}
			case DB_DOUBLE:
			{
				double *value = va_arg(args, double*);
				*value = sqlite3_column_double(this->stmt, i);
				break;
			}
			default:
				DBG1(DBG_LIB, "invalid result type supplied");
				return FALSE;
		}
	}
	return TRUE;
}

METHOD(database_t, query, enumerator_t*,
	private_sqlite_database_t *this, char *sql, ...)
{
	sqlite3_stmt *stmt;
	va_list args;
	sqlite_enumerator_t *enumerator = NULL;
	conn_t *conn;
	int i;

	conn = conn_get(this);
	if (!conn)
	{
		return NULL;
	}

	va_start(args, sql);
	stmt = run(conn->db, sql, &args);
	if (stmt)
	{
		INIT(enumerator,
			.public = {
				.enumerate = enumerator_enumerate_default,
				.venumerate = _sqlite_enumerator_enumerate,
				.destroy = _sqlite_enumerator_destroy,
			},
			.conn = conn,
			.stmt = stmt,
			.count = sqlite3_column_count(stmt),
			.database = this,
		);
		enumerator->columns = malloc(sizeof(db_type_t) * enumerator->count);
		for (i = 0; i < enumerator->count; i++)
		{
			enumerator->columns[i] = va_arg(args, db_type_t);
		}
	}
	else
	{
		conn_release(this, conn);
	}
	va_end(args);
	return (enumerator_t*)enumerator;
}

METHOD(database_t, execute, int,
	private_sqlite_database_t *this, int *rowid, char *sql, ...)
{
	sqlite3_stmt *stmt;
	conn_t *conn;
	int affected = -1;
	va_list args;

	conn = conn_get(this);
	if (!conn)
	{
		return -1;
	}

	va_start(args, sql);
	stmt = run(conn->db, sql, &args);
	va_end(args);
	if (stmt)
	{
		if (sqlite3_step(stmt) == SQLITE_DONE)
		{
			if (rowid)
			{
				*rowid = sqlite3_last_insert_rowid(conn->db);
			}
			affected = sqlite3_changes(conn->db);
		}
		else
		{
			DBG1(DBG_LIB, "SQLite execute failed: %s",
				 sqlite3_errmsg(conn->db));
		}
		sqlite3_finalize(stmt);
	}
	conn_release(this, conn);
	return affected;
}

METHOD(database_t, transaction, bool,
	private_sqlite_database_t *this, bool serializable)
{
	conn_t *conn;
	char *cmd = serializable ? "BEGIN EXCLUSIVE TRANSACTION"
							 : "BEGIN TRANSACTION";

	conn = conn_get(this);
	if (!conn)
	{
		return FALSE;
	}
	if (conn->transaction == TRANSACTION_NONE)
	{
		if (execute(this, NULL, cmd) == -1)
		{
			conn_release(this, conn);
			return FALSE;
		}
		conn->transaction = TRANSACTION_ACTIVE;
	}
	/* we don't release the connection until the transaction is done */
	return TRUE;
}

/**
 * Finalize a transaction depending on the reference count and if it should be
 * rolled back.
 */
static bool finalize_transaction(private_sqlite_database_t *this,
								 bool rollback)
{
	conn_t *conn;
	char *command = "COMMIT TRANSACTION";
	bool success;

	conn = conn_get(this);
	if (!conn || conn->transaction == TRANSACTION_NONE)
	{
		DBG1(DBG_LIB, "no database transaction found");
		if (conn)
		{
			conn_release(this, conn);
		}
		return FALSE;
	}

	if (rollback)
	{
		conn->transaction = TRANSACTION_ROLLBACK;
	}

	/* release the additional reference of this transaction */
	ignore_result(ref_put(&conn->refs));
	if (ref_cur(&conn->refs) == 1)
	{
		if (conn->transaction == TRANSACTION_ROLLBACK)
		{
			command = "ROLLBACK TRANSACTION";
		}
		success = execute(this, NULL, command) != -1;

		conn->transaction = TRANSACTION_NONE;
		conn_release(this, conn);
		return success;
	}
	conn_release(this, conn);
	return TRUE;
}

METHOD(database_t, commit_, bool,
	private_sqlite_database_t *this)
{
	return finalize_transaction(this, FALSE);
}

METHOD(database_t, rollback, bool,
	private_sqlite_database_t *this)
{
	return finalize_transaction(this, TRUE);
}

METHOD(database_t, get_driver, db_driver_t,
	private_sqlite_database_t *this)
{
	return DB_SQLITE;
}

METHOD(database_t, destroy, void,
	private_sqlite_database_t *this)
{
	this->pool->destroy_function(this->pool, (void*)conn_destroy);
	this->conn->destroy(this->conn);
	this->mutex->destroy(this->mutex);
	free(this->file);
	free(this);
}

/*
 * see header file
 */
sqlite_database_t *sqlite_database_create(char *uri)
{
	private_sqlite_database_t *this;
	conn_t *conn;
	char *file;

	if (sqlite3_threadsafe() == 0)
	{
		DBG1(DBG_LIB, "SQLite is compiled in single-thread mode, unable to use "
			 "connection pooling");
		return NULL;
	}

	/* parse sqlite:///path/to/file.db uri */
	if (!strpfx(uri, "sqlite://"))
	{
		return NULL;
	}
	file = uri + 9;

	INIT(this,
		.public = {
			.db = {
				.query = _query,
				.execute = _execute,
				.transaction = _transaction,
				.commit = _commit_,
				.rollback = _rollback,
				.get_driver = _get_driver,
				.destroy = _destroy,
			},
		},
		.pool = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.conn = thread_value_create(NULL),
		.file = strdup(file),
	);

	conn = conn_get(this);
	if (!conn)
	{
		destroy(this);
		return NULL;
	}
	conn_release(this, conn);
	return &this->public;
}

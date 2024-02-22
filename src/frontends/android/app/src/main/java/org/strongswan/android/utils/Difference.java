/*
 * Copyright (C) 2023 Relution GmbH
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

package org.strongswan.android.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import androidx.annotation.NonNull;
import androidx.arch.core.util.Function;
import androidx.core.util.Pair;

public class Difference<T>
{
	@NonNull
	private final List<T> inserts;
	@NonNull
	private final List<Pair<T, T>> updates;
	@NonNull
	private final List<T> unchanged;
	@NonNull
	private final List<T> deletes;

	@NonNull
	public static <K, V> Difference<V> between(
		@NonNull final List<V> existing,
		@NonNull final List<V> modified,
		@NonNull final Function<V, K> getKey)
	{
		final Map<K, V> existingMap = mapOf(existing, getKey);
		final Map<K, V> modifiedMap = mapOf(modified, getKey);

		final List<V> inserts = notIn(existingMap, getKey, modified);
		final List<V> deletes = notIn(modifiedMap, getKey, existing);
		final List<Pair<V, V>> updates = new ArrayList<>(modifiedMap.size());
		final List<V> unchanged = new ArrayList<>(existingMap.size());
		changeBetween(existingMap, modifiedMap, updates, unchanged);

		return new Difference<>(inserts, updates, unchanged, deletes);
	}

	@NonNull
	private static <K, V> Map<K, V> mapOf(
		@NonNull final List<V> list,
		@NonNull final Function<V, K> getKey)
	{
		final Map<K, V> map = new HashMap<>(list.size());

		for (final V entry : list)
		{
			final K key = getKey.apply(entry);
			map.put(key, entry);
		}

		return map;
	}

	@NonNull
	private static <K, V> List<V> notIn(
		@NonNull final Map<K, V> map,
		@NonNull final Function<V, K> getKey,
		@NonNull final List<V> list)
	{
		final List<V> filtered = new ArrayList<>(list.size());

		for (final V value : list)
		{
			final K key = getKey.apply(value);
			if (!map.containsKey(key))
			{
				filtered.add(value);
			}
		}

		return filtered;
	}

	@NonNull
	private static <K, V> void changeBetween(
		@NonNull final Map<K, V> existingMap,
		@NonNull final Map<K, V> modifiedMap,
		@NonNull List<Pair<V,V>> updates,
		@NonNull List<V> unchanged)
	{
		for (final Map.Entry<K, V> entry : modifiedMap.entrySet())
		{
			final V existingValue = existingMap.get(entry.getKey());
			final V modifiedValue = entry.getValue();

			if (existingValue != null && !Objects.equals(existingValue, modifiedValue))
			{
				final Pair<V, V> change = Pair.create(existingValue, modifiedValue);
				updates.add(change);
			}
			else if (existingValue != null)
			{
				unchanged.add(existingValue);
			}
		}

	}

	public Difference(
		@NonNull List<T> inserts,
		@NonNull List<Pair<T, T>> updates,
		@NonNull List<T> unchanged,
		@NonNull List<T> deletes)
	{
		this.inserts = inserts;
		this.updates = updates;
		this.unchanged = unchanged;
		this.deletes = deletes;
	}

	@NonNull
	public List<T> getInserts()
	{
		return inserts;
	}

	@NonNull
	public List<Pair<T, T>> getUpdates()
	{
		return updates;
	}

	@NonNull
	public List<T> getUnchanged()
	{
		return unchanged;
	}

	@NonNull
	public List<T> getDeletes()
	{
		return deletes;
	}

	public boolean isEmpty()
	{
		return inserts.isEmpty() && updates.isEmpty() && deletes.isEmpty();
	}

	@NonNull
	@Override
	public String toString()
	{
		return "Difference {" + inserts + ", " + updates + ", " + deletes + "}";
	}
}

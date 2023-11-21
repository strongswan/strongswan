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
		final List<Pair<V, V>> updates = changeBetween(existingMap, modifiedMap);

		return new Difference<>(inserts, updates, deletes);
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
	private static <K, V> List<Pair<V, V>> changeBetween(
		@NonNull final Map<K, V> existingMap,
		@NonNull final Map<K, V> modifiedMap)
	{
		final List<Pair<V, V>> changes = new ArrayList<>(modifiedMap.size());

		for (final Map.Entry<K, V> entry : modifiedMap.entrySet())
		{
			final V existingValue = existingMap.get(entry.getKey());
			final V modifiedValue = entry.getValue();

			if (existingValue != null && !Objects.equals(existingValue, modifiedValue))
			{
				final Pair<V, V> change = Pair.create(existingValue, modifiedValue);
				changes.add(change);
			}
		}

		return changes;
	}

	public Difference(
		@NonNull List<T> inserts,
		@NonNull List<Pair<T, T>> updates,
		@NonNull List<T> deletes)
	{
		this.inserts = inserts;
		this.updates = updates;
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
	public List<T> getDeletes()
	{
		return deletes;
	}

	public boolean isEmpty()
	{
		return inserts.isEmpty() && updates.isEmpty() && deletes.isEmpty();
	}
}

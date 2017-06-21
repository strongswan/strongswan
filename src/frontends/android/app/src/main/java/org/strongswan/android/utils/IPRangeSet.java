/*
 * Copyright (C) 2012-2017 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

/**
 * Class that represents a set of IP address ranges (not necessarily proper subnets) and allows
 * modifying the set and enumerating the resulting subnets.
 */
public class IPRangeSet
{
	private TreeSet<IPRange> mRanges = new TreeSet<>();

	/**
	 * Parse the given string (space separated subnets in CIDR notation) and return the resulting
	 * set or {@code null} if the string was invalid. And empty set is returned if the given string
	 * is {@code null}.
	 */
	public static IPRangeSet fromString(String ranges)
	{
		IPRangeSet set = new IPRangeSet();
		if (ranges != null)
		{
			for (String range : ranges.split("\\s+"))
			{
				try
				{
					set.add(new IPRange(range));
				}
				catch (Exception unused)
				{	/* besides due to invalid strings exceptions might get thrown if the string
					 * contains a hostname (NetworkOnMainThreadException) */
					return null;
				}
			}
		}
		return set;
	}

	/**
	 * Add a range to this set. Automatically gets merged with existing ranges.
	 */
	public void add(IPRange range)
	{
		if (mRanges.contains(range))
		{
			return;
		}
		reinsert:
		while (true)
		{
			Iterator<IPRange> iterator = mRanges.iterator();
			while (iterator.hasNext())
			{
				IPRange existing = iterator.next();
				IPRange replacement = existing.merge(range);
				if (replacement != null)
				{
					iterator.remove();
					range = replacement;
					continue reinsert;
				}
			}
			mRanges.add(range);
			break;
		}
	}

	/**
	 * Remove the given range from this set. Existing ranges are automatically adjusted.
	 */
	public void remove(IPRange range)
	{
		ArrayList <IPRange> additions = new ArrayList<>();
		Iterator<IPRange> iterator = mRanges.iterator();
		while (iterator.hasNext())
		{
			IPRange existing = iterator.next();
			List<IPRange> result = existing.remove(range);
			if (result.size() == 0)
			{
				iterator.remove();
			}
			else if (!result.get(0).equals(existing))
			{
				iterator.remove();
				additions.addAll(result);
			}
		}
		mRanges.addAll(additions);
	}

	/**
	 * Returns the subnets derived from all the ranges in this set.
	 */
	public Enumeration<IPRange> getSubnets()
	{
		return new Enumeration<IPRange>()
		{
			private Iterator<IPRange> mIterator = mRanges.iterator();
			private List<IPRange> mSubnets;

			@Override
			public boolean hasMoreElements()
			{
				return (mSubnets != null && mSubnets.size() > 0) || mIterator.hasNext();
			}

			@Override
			public IPRange nextElement()
			{
				if (mSubnets == null || mSubnets.size() == 0)
				{
					IPRange range = mIterator.next();
					mSubnets = range.toSubnets();
				}
				return mSubnets.remove(0);
			}
		};
	}

	/**
	 * Returns the number of ranges, not subnets.
	 */
	public int size()
	{
		return mRanges.size();
	}
}

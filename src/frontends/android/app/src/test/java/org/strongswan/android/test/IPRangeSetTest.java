/*
 * Copyright (C) 2017 Tobias Brunner
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

package org.strongswan.android.test;

import org.junit.Test;
import org.strongswan.android.utils.IPRange;
import org.strongswan.android.utils.IPRangeSet;

import java.net.UnknownHostException;
import java.util.Enumeration;

import static org.junit.Assert.assertEquals;

public class IPRangeSetTest
{
	private void assertSubnets(Enumeration<IPRange> subnets, IPRange...exp)
	{
		if (exp.length == 0)
		{
			assertEquals("no subnets", false, subnets.hasMoreElements());
			return;
		}
		for (int i = 0; i < exp.length; i++)
		{
			assertEquals("has subnet", true, subnets.hasMoreElements());
			assertEquals("range", exp[i], subnets.nextElement());
		}
		assertEquals("done", false, subnets.hasMoreElements());
	}

	@Test
	public void testEmpty()
	{
		IPRangeSet set = new IPRangeSet();
		assertEquals("size", 0, set.size());
		assertSubnets(set.getSubnets());
	}

	@Test
	public void testAddDistinct() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
		set.add(new IPRange("10.0.1.0/24"));
		assertEquals("size", 2, set.size());
		assertSubnets(set.getSubnets(), new IPRange("10.0.1.0/24"), new IPRange("192.168.1.0/24"));
	}

	@Test
	public void testAddAdjacent() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
		set.add(new IPRange("192.168.2.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"), new IPRange("192.168.2.0/24"));
	}

	@Test
	public void testAddAdjacentJoin() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		set.add(new IPRange("192.168.3.0/24"));
		assertEquals("size", 2, set.size());
		set.add(new IPRange("192.168.2.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"), new IPRange("192.168.2.0/23"));
	}

	@Test
	public void testAddSame() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
		set.add(new IPRange("192.168.1.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
	}

	@Test
	public void testAddLarger() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
		set.add(new IPRange("192.168.0.0/16"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.0.0/16"));
		set.add(new IPRange("0.0.0.0/0"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("0.0.0.0/0"));
	}

	@Test
	public void testAddLargerMulti() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		set.add(new IPRange("10.0.1.0/24"));
		set.add(new IPRange("255.255.255.255/32"));
		assertEquals("size", 3, set.size());
		set.add(new IPRange("0.0.0.0/0"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("0.0.0.0/0"));
	}

	@Test
	public void testRemoveNothing() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		set.remove(new IPRange("192.168.2.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
		set.remove(new IPRange("10.0.1.0/24"));
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
	}

	@Test
	public void testRemoveAll() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		set.remove(new IPRange("192.168.0.0/16"));
		assertEquals("size", 0, set.size());
		assertSubnets(set.getSubnets());
		set.add(new IPRange("192.168.1.0/24"));
		set.add(new IPRange("10.0.1.0/24"));
		set.add(new IPRange("255.255.255.255/32"));
		assertEquals("size", 3, set.size());
		set.remove(new IPRange("0.0.0.0/0"));
		assertEquals("size", 0, set.size());
		assertSubnets(set.getSubnets());
	}

	@Test
	public void testRemoveOverlap() throws UnknownHostException
	{
		IPRangeSet set = new IPRangeSet();
		set.add(new IPRange("192.168.1.0/24"));
		set.add(new IPRange("192.168.2.0/24"));
		set.remove(new IPRange("192.168.1.128", "192.168.2.127"));
		assertEquals("size", 2, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/25"), new IPRange("192.168.2.128/25"));
	}

	@Test
	public void testRemoveRangesIdent() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.1.0/24 192.168.4.0/24");
		set.remove(set);
		assertEquals("size", 0, set.size());
		assertSubnets(set.getSubnets());
	}

	@Test
	public void testRemoveRanges() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.0.0/16");
		IPRangeSet remove = IPRangeSet.fromString("192.168.1.0/24 192.168.3.0/24 192.168.16.0-192.168.255.255");
		set.remove(remove);
		assertEquals("size", 3, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.0.0/24"), new IPRange("192.168.2.0/24"),
					  new IPRange("192.168.4.0/22"), new IPRange("192.168.8.0/21"));
	}

	@Test
	public void testFromStringSingle() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.1.0/24");
		assertEquals("size", 1, set.size());
		assertSubnets(set.getSubnets(), new IPRange("192.168.1.0/24"));
	}

	@Test
	public void testFromString() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.1.0/24 fec1::/64	10.0.1.0/24 255.255.255.255");
		assertEquals("size", 4, set.size());
		assertSubnets(set.getSubnets(), new IPRange("10.0.1.0/24"), new IPRange("192.168.1.0/24"),
					  new IPRange("255.255.255.255/32"), new IPRange("fec1::/64"));
	}

	@Test
	public void testFromStringRange() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.1.0/24 10.0.1.0-10.0.1.16");
		assertEquals("size", 2, set.size());
		assertSubnets(set.getSubnets(), new IPRange("10.0.1.0/28"), new IPRange("10.0.1.16/32"),
					  new IPRange("192.168.1.0/24"));
	}

	@Test
	public void testFromStringInvalidPrefix() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.1.0/65");
		assertEquals("failed", null, set);
	}

	@Test
	public void testFromStringInvalidRange() throws UnknownHostException
	{
		IPRangeSet set = IPRangeSet.fromString("192.168.1.1 - 192.168.1.10");
		assertEquals("failed", null, set);
	}
}

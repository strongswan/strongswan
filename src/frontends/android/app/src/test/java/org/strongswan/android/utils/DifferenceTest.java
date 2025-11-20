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


import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

import java.util.List;
import java.util.Objects;

import androidx.core.util.Pair;

public class DifferenceTest
{
	@Test
	public void testElementAdded()
	{
		final Element element = new Element("a", 0);
		final List<Element> existing = List.of();
		final List<Element> modified = List.of(element);

		final Difference<Element> diff = Difference.between(existing, modified, Element::getKey);

		assertThat(diff.getInserts()).containsExactly(element);
		assertThat(diff.getUpdates()).isEmpty();
		assertThat(diff.getUnchanged()).isEmpty();
		assertThat(diff.getDeletes()).isEmpty();
	}

	@Test
	public void testElementRemoved()
	{
		final Element element = new Element("a", 0);
		final List<Element> existing = List.of(element);
		final List<Element> modified = List.of();

		final Difference<Element> diff = Difference.between(existing, modified, Element::getKey);

		assertThat(diff.getInserts()).isEmpty();
		assertThat(diff.getUpdates()).isEmpty();
		assertThat(diff.getUnchanged()).isEmpty();
		assertThat(diff.getDeletes()).containsExactly(element);
	}

	@Test
	public void testElementIdentical()
	{
		final Element element0 = new Element("a", 0);
		final Element element1 = new Element("a", 0);
		final List<Element> existing = List.of(element0);
		final List<Element> modified = List.of(element1);

		final Difference<Element> diff = Difference.between(existing, modified, Element::getKey);

		assertThat(diff.getInserts()).isEmpty();
		assertThat(diff.getUpdates()).isEmpty();
		assertThat(diff.getUnchanged()).containsExactly(element0);
		assertThat(diff.getDeletes()).isEmpty();
	}

	@Test
	public void testElementSwap()
	{
		final Element elementA = new Element("a", 0);
		final Element elementB = new Element("b", 0);
		final List<Element> existing = List.of(elementA);
		final List<Element> modified = List.of(elementB);

		final Difference<Element> diff = Difference.between(existing, modified, Element::getKey);

		assertThat(diff.getInserts()).containsExactly(elementB);
		assertThat(diff.getUpdates()).isEmpty();
		assertThat(diff.getUnchanged()).isEmpty();
		assertThat(diff.getDeletes()).containsExactly(elementA);
	}

	@Test
	public void testElementUpdate()
	{
		final Element elementA0 = new Element("a", 0);
		final Element elementA1 = new Element("a", 1);
		final List<Element> existing = List.of(elementA0);
		final List<Element> modified = List.of(elementA1);

		final Difference<Element> diff = Difference.between(existing, modified, Element::getKey);

		assertThat(diff.getInserts()).isEmpty();
		assertThat(diff.getUpdates()).containsExactly(Pair.create(elementA0, elementA1));
		assertThat(diff.getUnchanged()).isEmpty();
		assertThat(diff.getDeletes()).isEmpty();
	}

	private static class Element
	{
		private final String key;
		private final int value;

		public Element(final String key, final int value)
		{
			this.key = key;
			this.value = value;
		}

		public String getKey()
		{
			return key;
		}

		public int getValue()
		{
			return value;
		}

		@Override
		public boolean equals(Object o)
		{
			if (this == o)
			{
				return true;
			}
			if (o == null || getClass() != o.getClass())
			{
				return false;
			}
			Element element = (Element)o;
			return value == element.value && Objects.equals(key, element.key);
		}

		@Override
		public int hashCode()
		{
			return Objects.hash(key, value);
		}
	}
}

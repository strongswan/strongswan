package android.os;

import java.util.HashMap;
import java.util.Map;

public class Bundle
{
	private final Map<String, Object> map = new HashMap<>();

	public void putBoolean(final String key, final boolean value)
	{
		map.put(key, value);
	}

	public void putBundle(final String key, final Bundle bundle)
	{
		map.put(key, bundle);
	}

	public void putInt(final String key, final int value)
	{
		map.put(key, value);
	}

	public void putString(final String key, final String value)
	{
		map.put(key, value);
	}

	public boolean getBoolean(final String key)
	{
		final Object obj = map.get(key);
		if (obj != null)
		{
			return (boolean)obj;
		}
		return false;
	}

	public Bundle getBundle(final String key)
	{
		return (Bundle)map.get(key);
	}

	public int getInt(final String key)
	{
		final Object obj = map.get(key);
		if (obj != null)
		{
			return (int)obj;
		}
		return 0;
	}

	public String getString(final String key)
	{
		return getString(key, null);
	}

	public String getString(final String key, final String fallback)
	{
		final Object obj = map.get(key);
		if (obj != null)
		{
			return (String)obj;
		}
		return fallback;
	}
}

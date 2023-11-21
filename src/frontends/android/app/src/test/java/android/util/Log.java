package android.util;

public class Log
{
	public static int d(String tag, String msg)
	{
		System.out.println("DEBUG: " + tag + ": " + msg);
		return 0;
	}

	public static int w(String tag, String msg)
	{
		System.out.println("WARN: " + tag + ": " + msg);
		return 0;
	}
}

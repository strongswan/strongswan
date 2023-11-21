package android.database.sqlite;

public class SQLiteQueryBuilder
{
	public static void appendColumns(StringBuilder s, String[] columns)
	{
		boolean first = true;
		for (String column : columns)
		{
			if (!first)
			{
				s.append(",");
			}
			s.append(column);
			first = false;
		}
	}
}

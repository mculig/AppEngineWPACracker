package cc.paas;

public class Result {
	
	Long DictionaryEntries;
	Long EntriesChecked;
	Long PasswordFound;
	String Password;
	
	public Result(Long DictionaryEntries, Long EntriesChecked, Long PasswordFound, String Password)
	{
		this.DictionaryEntries=DictionaryEntries;
		this.EntriesChecked=EntriesChecked;
		this.PasswordFound=PasswordFound;
		this.Password=Password;
	}
	
	public Result(Integer DictionaryEntries, Integer EntriesChecked, Integer PasswordFound, String Password)
	{
		this.DictionaryEntries=Long.valueOf(DictionaryEntries);
		this.EntriesChecked=Long.valueOf(EntriesChecked);
		this.PasswordFound=Long.valueOf(PasswordFound);
		this.Password=Password;
	}

}

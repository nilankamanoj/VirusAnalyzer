/*
sample rule to check in sample infected file
*/
rule sample_string
{
	meta:
		author="Nilanka Manoj"
		date="27/05/218"
		description="sample string 'aa2' "
		
	strings:
		$signature1="aa2"
		
		
	condition:
		$signature1
}
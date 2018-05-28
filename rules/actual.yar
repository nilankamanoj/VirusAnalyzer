/*
here defines some actual malware signatures that identified by various institutes and authorities.
we can add milions of signatures and update daily these yara rules and scan for almost all theats.
*/
rule DarkEYEv3_Cryptor {
	meta:
		description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
		author = "Florian Roth"
		reference = "http://darkeyev3.blogspot.fi/"
		date = "2015-05-24"
		hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
		hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
		hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
		hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
		hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
		hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
		hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
		hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
		hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"
		score = 55
	strings:
		$s0 = "\\DarkEYEV3-" 
	condition:
		uint16(0) == 0x5a4d and $s0
}
rule AnglerEKredirector : EK
{
   meta:
      description = "Angler Exploit Kit Redirector"
      ref = "http://blog.xanda.org/2015/08/28/yara-rule-for-angler-ek-redirector-js/"
      author = "adnan.shukor@gmail.com"
      date = "08-July-2015"
      impact = "5"
      version = "1"
   strings:
      $ekr1 = "<script>var date = new Date(new Date().getTime() + 60*60*24*7*1000);" fullword
      $ekr2 = "document.cookie=\"PHP_SESSION_PHP="
      $ekr3 = "path=/; expires=\"+date.toUTCString();</script>" fullword
      $ekr4 = "<iframe src=" fullword
      $ekr5 = "</iframe></div>" fullword
   condition:
      all of them
}
rule angler_html : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Angler Exploit Kit Detection"
   hash0 = "afca949ab09c5583a2ea5b2006236666"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = " A9 3E AF D5 9AQ FA 14 BC F2 A0H EA 7FfJ A58 A3 B1 BD 85 DB F3 B4 B6 FB B2 B4 14 82 19 88 28 D0 EA 2"
   $string1 = " 2BS 25 26p 20 3F 81 0E D3 9C 84 C7 EC C3 C41M C48 D3 B5N 09 C2z 98 7B 09. DF 05 5EQ DF A3 B6 EE D5 "
   $string2 = "9 A1Fg A8 837 9A A9 0A 1D 40b02 A5U6 22o 16 DC 5D F5 F5 FA BE FB EDX F0 87 DB C9 7B D6 AC F6D 10 1AJ"
   $string3 = "24 AA 17 FB B0 96d DBN 05 EE F6 0F 24 D4 D0 C0 E4 96 03 A3 03 20/ 04 40 DB 8F 7FI A6 DC F5 09 0FWV 1"
   $string4 = "Fq B3 94 E3 3E EFw E6 AA9 3A 5B 9E2 D2 EC AF6 10c 83 0F DF BB FBx AF B4 1BV 5C DD F8 9BR 97v D0U 9EG"
   $string5 = "29 9B 01E C85 86 B0 09 EC E07 AFCY 19 E5 11 1C 92 E2 DA A9 5D 19P 3A BF AB D6 B3 3FZ B4 92 FF E1 27 "
   $string6 = "B A9 88 B8 F0 EBLd 8E 08 18 11P EE BFk 15 5BM D6 B7 CEh AF 9C 8F 04 89 88 5E F6 ED 13 8EN1p 86Vk BC "
   $string7 = "w F4 C8 16pV 22 0A BB EB 83 7D BC 89 B6 E06 8B 2A DC E6 7D CE. 0Dh 18 0A8 5E 60 0C BF A4 00M 00 E3 3"
   $string8 = "B7 C6 E3 8E DC 3BR 60L 94h D8 AA7k5s 0D 7Fb 8B 80P E0 1BP EBT B5 03zE D0o 2A B97 18 F39 7C 94 99 11 "
   $string9 = "kY 24 8E 3E 94 84 D2 00 1EB 16 A4 9C 28 24 C1B BB 22 7D 97c F5 BA AD C4 5C 23 5D 3D 5C A7d5 0C F6 EA"
   $string10 = "08 01 3A 15 3B E0 1A E2 89 5B A2 F4 ED 87O F9l A99 124 27 BF BB A1c 2BW 12Z 07 AA D9 81 B7 A6-5 E2 E"
   $string11 = " 16 BF A7 0E 00 16 BB 8FB CBn FC D8 9C C7 EA AC C2q 85n A96I D1 9B FC8 BDl B8 3Ajf 7B ADH FD 20 88 F"
   $string12 = "  ML    "
   $string13 = " AEJ 3B C7 BFy EF F07X D3 A0 1E B4q C4 BE 3A 10 E7 A0 FE D1Jhp 89 A0sj 1CW 08 D5 F7 C8 C6 D5I 81 D2 "
   $string14 = "B 24 90 ED CEP C8 C9 9B E5 25 09 C6B- 2B 3B C7 28 C9 C62 EB D3 D5 ED DE A8 7F A9mNs 87 12 82 03 A2 8"
   $string15 = "A 3A A2L DFa 18 11P 00 7F1 BBbY FA 5E 04 C4 5D 89 F3S DAN B5 CAi 8D 0A AC A8 0A ABI E6 1E 89 BB 07 D"
   $string16 = "C B5 FD 0B F9 0Ch CE 01 14 8Dp AF 24 E0 E3 D90 DD FF B0 07 2Ad 0B 7D B0 B2 D8 BD E6 A7 CE E1 E4 3E5 "
   $string17 = "19 0C 85 14r/ 8C F3 84 2B 8C CF 90 93 E2 F6zo C3 D40 A6 94 01 02Q 21G AB B9 CDx 9D FB 21 2C 10 C3 3C"
   $string18 = "FAV D7y A0 C7Ld4 01 22 EE B0 1EY FAB BA E0 01 24 15g C5 DA6 19 EEsl BF C7O 9F 8B E8 AF 93 F52 00 06 "
condition:
   18 of them
}
rule Exploit_MS15_077_078: Exploit {
	meta:
		description = "MS15-078 / MS15-077 exploit - generic signature"
		author = "Florian Roth"
		reference = "https://code.google.com/p/google-security-research/issues/detail?id=473&can=1&start=200"
		date = "2015-07-21"
		hash1 = "18e3e840a5e5b75747d6b961fca66a670e3faef252aaa416a88488967b47ac1c"
		hash2 = "0b5dc030e73074b18b1959d1cf7177ff510dbc2a0ec2b8bb927936f59eb3d14d"
		hash3 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
		hash4 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
	strings:
		$s1 = "GDI32.DLL" fullword ascii
		$s2 = "atmfd.dll" fullword wide
		$s3 = "AddFontMemResourceEx" fullword ascii
		$s4 = "NamedEscape" fullword ascii
		$s5 = "CreateBitmap" fullword ascii
		$s6 = "DeleteObject" fullword ascii

		$op0 = { 83 45 e8 01 eb 07 c7 45 e8 } /* Opcode */
		$op1 = { 8d 85 24 42 fb ff 89 04 24 e8 80 22 00 00 c7 45 } /* Opcode */
		$op2 = { eb 54 8b 15 6c 00 4c 00 8d 85 24 42 fb ff 89 44 } /* Opcode */
		$op3 = { 64 00 88 ff 84 03 70 03 }
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or all of ($op*)
}

rule Exploit_MS15_077_078_HackingTeam: Exploit {
	meta:
		description = "MS15-078 / MS15-077 exploit - Hacking Team code"
		author = "Florian Roth"
		date = "2015-07-21"
		super_rule = 1
		hash1 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
		hash2 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
	strings:
		$s1 = "\\SystemRoot\\system32\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\sysnative\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "CRTDLL.DLL" fullword ascii
		$s5 = "\\sysnative" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "InternetOpenA coolio, trying open %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and all of them
}
rule Mal_Dropper_httpEXE_from_CAB : Dropper {
	meta:
		description = "Detects a dropper from a CAB file mentioned in the article"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 60
		hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"
	strings:
		$s1 = "029.Hdl" fullword ascii
		$s2 = "http.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) )
}

rule Mal_http_EXE : Trojan {
	meta:
		description = "Detects trojan from APT report named http.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 80
		hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"
	strings:
		$x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
		$x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
		$x3 = "\\dumps.dat" fullword ascii
		$x4 = "\\wordpade.exe" fullword ascii
		$x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
		$x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii /* base64: pKY1[1 */

		$s1 = "SELECT * FROM moz_logins;" fullword ascii
		$s2 = "makescr.dat" fullword ascii
		$s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
		$s4 = "?moz-proxy://" fullword ascii
		$s5 = "[%s-%s] Title: %s" fullword ascii
		$s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
		$s7 = "Windows 95 SR2" fullword ascii
		$s8 = "\\|%s|0|0|" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 2 of ($s*) ) ) or ( 3 of ($x*) )
}
rule attachment : mail {
	meta:
		author = "A.Sanchez <asanchez@koodous.com>"
		description = "Detects scam emails with phishing attachment."
		test1 = "email/eml/transferencia1.eml"
		test2 = "email/eml/transferencia2.eml"

	strings:
		$filename = "filename=\"scan001.pdf.html\""
		$pleaseEnter = "NTAlNkMlNjUlNjElNzMlNjUlMjAlNjUlNkUlNzQlNjUlNzIlMjAlN" // Please enter 
		$emailReq = "NkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUlNzglMzIlMkUlNDUlNkQlNjElNjklNkMlM0I" // ment.index2.Email;
		$pAssign = "NzAlMjAlM0QlMjAlNjQlNkYlNjMlNzUlNkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUl" // p = document.inde
		
	condition:
		all of them
}
rule with_images : mail {
	meta:
		author = "Antonio Sanchez <asanchez@hispasec.com>"
		reference = "http://laboratorio.blogs.hispasec.com/"
		description = "Rule to detect the presence of an or several images"
	strings:
                $eml_01 = "From:"
                $eml_02 = "To:"
                $eml_03 = "Subject:"
		$img_a = ".jpg" nocase
		$img_b = ".png" nocase
		$img_c = ".bmp" nocase
	condition:
                all of ( $eml_* ) and
		any of ( $img_* )
}
rule IronTiger_ASPXSpy
{
    
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "ASPXSpy detection. It might be used by other fraudsters"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "ASPXSpy" nocase wide ascii
        $str2 = "IIS Spy" nocase wide ascii
        $str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
    
    condition:
        any of ($str*)
}

rule IronTiger_ChangePort_Toolkit_driversinstall 
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Changeport Toolkit driverinstall"   
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "openmydoor" nocase wide ascii
        $str2 = "Install service error" nocase wide ascii
        $str3 = "start remove service" nocase wide ascii
        $str4 = "NdisVersion" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ChangePort_Toolkit_ChangePortExe 
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Toolkit ChangePort"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "Unable to alloc the adapter!" nocase wide ascii
        $str2 = "Wait for master fuck" nocase wide ascii
        $str3 = "xx.exe <HOST> <PORT>" nocase wide ascii
        $str4 = "chkroot2007" nocase wide ascii
        $str5 = "Door is bind on %s" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}


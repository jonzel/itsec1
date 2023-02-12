# IT SEC Ankis

## Was sind die Grundziele der Informationssicherheit?

* Confidentiality (Vertraulichkeit): Vertraulichkeit ist der Schutz vor unbefugter Preisgabe von Informationen. Vertraulichen Daten und Informationen duerfen ausschliesslichen Befugten in der zulaessigen Weise zugaenglich sein. 
* Integrity (Integritaet): Sicherstellung der Unversehrtheit/Korrektheit der Information
* Availablity (Verfuegbarkeit): Dienste oder Daten gelten als verfuegbar, wenn diese stets wie vorgesehen bereitgestellt werden koennen.

## Was sind symmetrische krypographisches Algorithmen?

Transformation von Eingabedaten durch einen spezifischen Algorithmus, der zum Ver-/Entschluesseln den gleichen Schluessel benutzt

## Was sind asymmetrische krypographisches Algorithmen?

Transformation von Eingabedaten durch einen spezifischen Algorithmus, der zum Ver-/Entschluesseln zwei verschiedene Schluessel benutzt

## Was sind Modifikationsekennungswerte?

Modification Detection Codes (MDC) sind der kryptographische Fingerabdruck einer Nachricht

## Was sind Nachrichtenauthentisierungswerte?

Message Authentification Codes (MAC) ermoeglichen zusaetzlich die Verifikation der Authentizitaet einer Nachricht`

## Was ist der Unterschied zwischen MDCs und MACs?

* MDCs werden verwendet, um Änderungen an einer Nachricht zu erkennen
* MACs verwendet werden, um den Ursprung einer Nachricht zu authentifizieren

## Was ist eine Hashfunktion?

Funktion h, die

1. Kompression: h bildet Eingaben mit bel. Laenge auf Ausgabewerte fester Bitlaenge ab
2. Einfacheit der Berechung

## Was ist ein kryptographische Hashfunktion?

Hashfunktion h, die

1. Unbestimmbarkeit von Urbildern
2. Unbestimmtbarkeit eines 2. Urbildes (Kollisionen finden)
3. Kollisionsfreiheit

## Was sind die Eigenschaften eines Alg. zur MAC-Berechnung?

MAC-Algorithmen erfordern zwei Eingabeparameter:

1. Die zu schützenden Daten
2. Einen geheimen Schlüssel

Berechnung Prüfsumme aus beiden Werten (den MAC)

## Wie funktioniert Passwort Speicherung mit Salt/Pepper

Salt:

* Passwort wird mit Salt zusammen gehasht
* Salt eindeutig fuer jeden Account
* Nicht unbedingt geheim

Pepper:

* Zufaellige Zeichenkette
* Nicht in Passwort Datenbank gespeichert
* Hardcoded im System oder Config Datei

## Was ist sind Rainbow Tables?

* Ansatz: Alle Passwort Hashes speichern (Problem Speichergroesse)
* Definiere Ketten aus Hash- und Reduzierfunktionen und speichere nur den Anfangs- und Endwert

## Was sind die Schritte bei einem Rainbow Table?

1. Erstellen des RT 
2. Hashwert liegt vor
3. Hashwert ist in RT => Klartext kann berechnet werden
4. Hashwert ist nicht in RT => Eine Iteration aus Hash + Reduce anwenden, Ergebnis in RT? Falls nein, erneute Iteration

## Was ist das AES Verfahren?

* AES  = Advanced Encryption Standard
* Symmetrisch
* Blockgroesse 128 bits

## Wie funktioniert das AES Verfahren?

1. Schluesselerweiterung
2. Initial Round
3. Main Rounds (Kombination aus Substitution und Permutation)
4. Final Rounds
5. Output

## Was sind Moeglichkeiten fuer Kryptoanalyse bei symmetrischen Verfahren?

1. Brute-Force
2. Known Cipher Text
3. Suche anhand bekannter Klartext-Schluesseltext Paare
4. Analyse auf Basis gewaehlter Klartexte
5. Gewaehler Schluesseltexte
6. Statistische Angriffe

## Was ist das Kerckhoffs'sche Prinzip?

Die Sicherheit eines (symmetrischen) Verschlüsselungsverfahrens muss auf der Geheimhaltung des Schlüssels beruhen anstatt auf der Geheimhaltung des Verschlüsselungsalgorithmus.

## Was sind die Ziele von asymmetrischen Chiffren?

* Einfache Erzeugung von Schluesselpaaren
* Veroeffentlichung von Schluesseln soll moeglich sein
* Keine Ableitung des privaten Schluessels
* Zielabhaengige Verschluesselung von Daten
* Sicherung der Vertraulichkeit der Daten

## Was sind die schritte bei RSA?

1. Schluesselpaar generieren
2. Verschluesselung
3. Entschluesselung

## Wie werden bei RSA Schluessel erzeugt?

1. Wahl eines RSA-Modulus n = p * q (p, q prim)
2. Berechnung der Eulerischen Phi-Funktion von n
3. Finde oeffentlichen Exponenten e, sodass
    * 1 < e < phi(n)
    * ggt(e,phi(n)) = 1
    * Dann: (n,e) ist der oeffentliche Schluessel
4. Erzeugung des privaten Exponenten e*d = mod phi(n), dann (n,d) privater Schlüssel

## Wie wird RSA verschlüsselt/entschlüsselt?

1. Schlüsselaustausch  von A zu B
2. Umwandlung des Textes
3. c = m^e mod n
4. Übertragung

dann

1. Berechnung m = c^d mod n
2. Text rück umwandeln

## Was sind Angriffe auf RSA?

* Brute-Force
* Chosen-Chiper-Text
* Timing Angriff

## Was ist der Ablauf bei einem Diffie-Hellman Schlüsselaustausch?

1. Austausch von q prim, a primite Wurzel von q
2. Bob & Alice definieren private Schlüssel u, w
3. Austausch von X_Bob = a^u mod q und X_Alice = a^w mod q
4. Alice und Bob berechnen:
    * K_session = (X_Alice)^u mod q
    * K_session = (X_Bob)^w mod q

## Was ist prolematisch an Diffie-Hellman?

* Keine Authentizitaet gewaehrleitet
* Loesung: Wechselseitige Authentifizierung anhand von Zertifikaten

## Was sind Anforderungen an Signaturen?

* Identifikation/Verbindlichkeit
* Echtheit
* Abschluss
* Warnung
* Keine Wiederverwendbarkeit
* Unveränderbarkeit

## Was ist eine Replay Attacke?

* Angriff auf Authentizitaet einer Nachricht
* Angreifer sendet aufgezeichnete Daten nochmals an den Empfaenger und kann so die Authentizitaet der Nachricht angreifen
* Loesung: Zeitstempel

## Was ist Public Key Infrastructure?

A PKI consists of:

* Certificate authority (CA) that stores, issues and signs the digital certificates;
* Registration authority (RA) which verifies the identity of entities requesting their digital certificates to be stored at the CA;
* Central directory—i.e., a secure location in which keys are stored and indexed;
* Certificate management system managing things like the access to stored certificates or the delivery of the certificates to be issued;
* Certificate policy stating the PKI's requirements concerning its procedures. Its purpose is to allow outsiders to analyze the PKI's trustworthiness.


## Was ist Authentizitaet?

* ist die Echtheit bzw. Glaubwuerdigkeit, die anhand einer eindeutigen Identitaet bzw. charakteristischen Merkmalen ueberprueft wird

## Was ist Authentisierung?

* ist der Nachweis der Identitaet eines Subjekts

## Was ist Authentifikation?

* ist die Ueberpruefung einer behaupteten Authentisierung mit geeigneten Massnahmen
* drei Faelle:
  1. Authentifikation des Datenursprungs
  2. Benutzerauthentifikation
  3. Beidseitige Authentifikation

## Was sind Eigenschafte von Authentifikationsverfahren?

* Something you have, something you know, something you are, somewhere you are

## Was ist der Unterschied zwischen Authentifizierung und Authorisierung?

* Authentifizierung = verifiziert die Identitaet einer Person/Systems
* Authorisierung = Genehmigung zur Einzelfunktion eines Systems

## Was ist das Challenge-Response Verfahren (symmetrisch)?

Frage/Antwort Protokoll, nur zur Authentifikation

* Client hat K_CID Keys, Enc Verschlüsselungsfunktion, CID Card ID
* Server hat alle Keys und Enc

1. Client sendet CID
2. Server schickt zufällige Zahl r zurück
3. Beide Berechnen Enc_K_CID(r)
4. Server vergleicht Ergebnis von Client


## Was ist das Challenge-Response Verfahren (asymmetrisch)?

Frage/Antwort Protokoll, nur zur Authentifikation

* Client hat K_CID Keys, Enc Verschlüsselungsfunktion, CID Card ID
* Server hat alle Keys und Enc

1. Client sendet CID
2. Server schickt zufällige Zahl r zurück
3. Client berechnet Enc_K^D_CID(r) = Sign
4. Server prüft Dec_K^D_CID(Sign) = r

## Was sind die Schritte im S/Key Verfahren?

verkettete Hashfunktionionen

Phase 1: Initialisierungsphase (s=Passwort, k=Seed-Wert), dann

* Clientrechner generiert: p_i = Hash_i(s,k)
* p_0 = sha3(s,k), p_1 = sha3(sha3(s,k),k), usw,...
* client schickt p_n und k zum Server

Phase 1: Authentifikationsphase

1. Anfrage Login, Server kennt p_i
2. Server fragt nach p_i-1
3. Client berechnet p_i-1 = Hash_i-1(Hash_i-2(..., k), k)
4. Client schickt p_i-1
5. Server prüft Hash(p_i-1,k) == p_i
6. Server iteriert i

## Was sind aktive biometrische Merkmale?

Stimmerkennung, Tastaturanschlag, Bewegung, Unterschrift, EKG

## Was sind passive biometrische Merkmale?

Fingerabdruck, Retina/Iris Muster, Handvenen, Gesichtserkennung, Handgeometrie, DNS, DNA

## Was muss bei biometrischen Authentifikationsverfahren abgewogen werden?

* FAR  = # falscher Akzeptanzen / # aller unberechtigen Versuche
* FRR = # falscher Abweisungen / # aller berechtiger Versuche
* Die Akzeptanzschwelle bestimmt die Kurve aus FAR und FRR

## Was sind Merkmale von Fingerabdrücken?

* Auf Basis von Minuzien
* Orientierung, Lage relativ zu anderen Minuzien oder relativ zu ROIs
* ROIs zB Ridge Endings, Bifurcations
* Authentifikation durch Extraktion der Merkmale

##  Was sind bei Kerberos Realsm, Principals und Tickets?

* Realm = Administrative Domäne (e.g. Domainname in Capital)
* Principal = Eindeutiger Indentifizierer (alice/admin@REALM)
* Ticket = von AS bereitgestellter Ausweis zur Nutzung mit Verfallszeit

## Was sind die Komponenten in Kerberos?

* Key Distribution Center (KDC)
* Ticket Granting Server (TGS)
* Authentification Server (AS)

## Was sind die Schritte bei Kerberos Authentifikation?

1. Anfrage TGT
2. Prüfung, ob Nutzer bekannt in DB, dann TGT Response
3. Service Ticket Request
4. Service Ticket Bearbeitung
5. Application Request mit mit Authenticator
    * Application Response

## How the Kerberos architecture work?

1. A client wants to access a server over the network. The client first requests a ticket from the Authentication Server (AS).
2. The AS verifies the client's identity and, if it is valid, generates a ticket-granting ticket (TGT) that contains information about the client, a session key, and a ticket-granting service (TGS) session key. The TGT is encrypted using the client's password as the key.
3. The client decrypts the TGT using its password and sends a request for a service ticket to the TGS.
4. The TGS verifies the client's identity and generates a service ticket that contains information about the client, the session key, and the server's network address. The service ticket is encrypted using the TGS's secret key.
5. The client sends the service ticket to the server, along with an authentication request.
6. The server decrypts the service ticket and verifies the client's identity. If the client's identity is valid, the server grants access to its resources.
7. The client and server can now securely communicate using the session key contained in the service ticket.

## Was sind Schwachstellen bei Kerberos?

* AS, TGS, Application müssen zeitsynchron sein
* Passwort bestimmt Sicherheitslevel
* Keine Inegritätsprüfung der Nachrichten

## Was sind die Kernkomponenten bei Shibboleth?

* Identity Provider (Bei Heimateinrichtung)
* Service Provider (Beim Diensterbringer)
* Discoveryservice (Lokalisierungsdienst)

## Was ist der Ablauf bei Shibboleth Anmeldung?

1. Anfrage an Dienst
2. Umleitung zum Discovery Dienst mit SAML-Login-Message
3. Aufruf Seite Discovery Service
4. Weiterleitung IDP Heimatorganisation
5. Aufruf+Eingabe IDP Login Seite
    * IDP prüft SAML-Message
    * Setzt Login-Cookie
6. Senden des Login SAML-Message
7. SP validiert SAML-Message
8. SP prüft
9. Freigegebene Userdaten
10. Loginvorgang erfolgreich

Welche Begriffe sind Teil der OAuth 2.0 Terminologie?

* Ressource Server (Dienst, der die geschützten Daten enthält)
* Ressource Owner (Org Einheit, der die Daten gehören)
* Client/Application (im Namen des Resource Owner zugreifende Anwendung)
    * Public/confidential Client
* Authorization Server (Dienst, dem der RS vertraut, um Clients zu authorisieren)
* Authorization Code (Einmaliges Zwischengeheimnis für Client, um AT und RT zu erhalten)
* Access Token (Geheimnis für den Zugriff auf die API)
* Refresh Token (Optionales Geheimnis, um AT zu erneuern)

## Welche Einsatzvarianten gibt es bei OAuth 2.0?

* Authorization code grant
* Implicit grant
* Resource owner grant
* Client credentials grant 

## Wie ist das ISO/OSI Modell in der Kommunikation aufgebaut?

* Schicht 1 – Bitübertragungsschicht (Physical Layer)
* Schicht 2 – Sicherungsschicht (Data Link Layer)
* Schicht 3 – Vermittlungsschicht (Network Layer)
* Schicht 4 – Transportschicht (Transport Layer)
* Schicht 5 – Sitzungsschicht (Session Layer)
* Schicht 6 – Darstellungsschicht (Presentation Layer)
* Schicht 7 – Anwendungsschicht (Application Layer)

## Wie ist das TCP/IP Referenzmodell aufgebaut?

* Layer 1: Netzzugangsschicht (Ethernet, Token Ring, ARP, AC, PPP)
* Layer 2: Internetschicht (IP, IPX, ICMP)
* Layer 3: Transportschicht (TCP, UDP)
* Layer 4: Anwendungsschicht (HTTP(S), FTP, RMI)

## Aus welchen Komponenten besteht ein Netzwerk?

* Broadcastdomäne
* Kollisionsdomäne
* Repeater
* Hub
* Bridge
* L2-Switch
* Router
* L3-Switch

## Was ist die Broadcastdomäne?

Logischer Verbund von Netzwerkgeräten, bei denen ein Broadcast alle Geräte erreicht

## Was ist Kollisionsdomäne?

Verbund von physischen Netzwerkgeräten, die sich ein gemeinsames Übertragungsmedium teilen

## Was ist ein Repeater?

* Einfaches Netzwerkgerät zur Verlängerung der Reichweite
* Besitzt nur 2 Anschlüsse

## Was ist ein Hub?

* Multiport-Repeater
* Signale werden an alle Geräte weitergeleitet

## Was ist ein Bridge?

* Verbindet 2 physische Netze miteinander durch 2 Asnchlüsse
* Signale werden als Frames interpretiert
* Leiter Frames nur bei Bedarf weiter

## Was ist ein L2-Switch?

* Multiport Bridge (Bridge mit mehreren Anschlüssen)
* Frames werden gefiltert und nur an relevante Ports geleitet

## Was ist ein Router?

* Netzwerkgerät zur Weiterleitung von Datenpacketen zwischen logischen Netzwerken
* i.d.R. LAN und WLAN

## Was ist ein L3-Switch

* Multiport-Router

## Was sind Layer 2 Aufgaben?

* Ver/entpacken ovn Paketen aus der Vermittlungsschicht
* Fehlererkennung der Bitübertragung durch Prüfsummen
* Bereitstellen der Media Access Control (MAC) Adressen (FF:FF:FF:FF:FF:FF) (6 Bytes)

## Was sind die Aufgaben eines L2-Switches?

* erlernen lokale MAC Adressen (MAX <-> Port)
* Paketweiterleitung nur an den betroffenen Ports aus Tabelle oder alle (zb falls MAC nicht bekannt oder Broadcasting Frame)
* Forwarding durch Store-and-Forward

## Was macht ein VLAN?

= Virtual Local Area Network

* Segmentierung eines physischen Layer 2 Netzes ohne Einsatz weiterer Layer 1 Netze
* VLAN Tag im Ethernet-Frame

## Was ist das Adress-Resolution-Protocol?

* Ziel: Auflösen logischer IPv4-Adressen aus Layer 3 in (physische) MAC Adressen
* 2 Phasen:
    1. ARP-Request (falls MAC nicht in ARP-Cache, Request an Broadcast MAC Adresse)
    2. ARP-Reply
* Gratuitous ARP (Ziele IP-Konfliktprüfung), ARP-Cache Update bei Nachbarn oder MAC-Tabelle im Switch

## Was ist ARP-Spoofing?

1. Lauschen nach IP- und MAC-Adresse des Opfers
2. Angreifer sendet Frame mit ARP Reply mit korrekter Absender und Empfaenger MAC, aber mit manipulierter IP-Adresse (boradcast)
3. Das ARP Cache wird mit den manipulierten Adressen gefuellt
4. Das Opfer liest die manipulierte IP-Adresse aus


## Wie kann man sich vor ARP Spoofing schützen?

* Statische ARP
* Port-Sicherheit: Konfigurieren der Portsicherheit auf Netzwerk-Switches, um die Anzahl der MAC-Adressen zu begrenzen, die einem bestimmten Port zugeordnet werden können. Nicht autorisierte Geräte koennen keine falschen ARP-Nachrichten senden.
* Netzwerksegmentierung: Implementierung einer Netzwerksegmentierung (VLANs) fuer isolierte Subnetze zu schaffen

## In welchem Layer findet eine ARP Attacke statt?

Layer 2

## Was sind Layer 3 Eigenschaften?

* Fragmentierung der Daten aus der Transport Schicht
* Detektion von L3-Datagrams aus der Sicherungsschicht
* Bereitstellung logischer Adressen für Geräte
* Routing: Selektion des besten Wegs für den Paketverlauf zwischen Routern oder L3-Switches
* Forwarding: Weiterleitung zwischen logischen Netzen

## Was sind die Eigenschaften von Internet Protokoll (IP)

* Best-Effort-Delivery
* Es muss keine Verbindung zwischen Sender und Empfaenger vor Absenden aufgebaut werden
* Keine Garantie der Paketzustellung
* Basiert auf (stateless) IP-Paketen/Datagrams 

## Was sind die Adressierungsmöglichkeiten bei IP?

* Unicast (an einen Empfänger in der Domäne)
* Multicast (an mehrere Empfänger einer Domäne)
* Broadcast (an alle)
* Anycast (an all gerichtet, aber es gibt nur einen Empfänger)

## Was sind die Komponenten eines IPv4 Frames?

* IP Header Length
* Type of service
* Paketlänge
* Kennung
* Flags 
* Fragment Offset
* Protokol ID

## Was ist IP-Spoofing?

* Idee: Manipulation der Source IP eines IP-Paketes
* Basis fuer DDoS/DRDoS und Spoofing Angriffe (MITM)
* Sender-IP auf dem Frame wird manipuliert

## Was ist der Unterschied zwischen DDoS und DDRoS?

* DDOS = Distributed Denial of Service
* DDRoS = Distributed Reflective Denial of Service

* DDOS = Last durch Requests
* DRDOS = Last durch große Response

## Was sind die Aufgaben von Layer 4?

* Transportschicht
* Bereitstellung von Ende-zu-Ende Protokollen fuer Internet Kommunikation
* Ver/entpacken der Daten aus Anwendungsschicht in Segmenten
* Adressierung dre Prozesse eines Hosts durch zb Ports
* Optional:
  * Etablierung eines verbindungsorientierten Kommunikationswegs
    * Garantierte Datenübertragung
    * Einhaltung der Segmentreihenfolge
    * Datenflusskontrolle

## Was sind Layer 4 Standardports?

Auswahl:

* 22/TCP: SSH
* 53/TCP: DNS
* 80/TCP: HTTP
* 443/TCP: HTTPS

## Was sind Eigenschaften des Transmission Control Protocol?

* Idee: Sicherer Transport von Daten durch unzuverlaessige Netzwerke
* RFC
* Zuverlaessig
* Verbindungsorientiert (logische Ende-zu-Ende Verbindung), 3-Wege Handshake fuer Verbindung
* TCP transportiert Bytestroeme hoeherer Layer in Segementen
* Basierend auf dem IP (mit Erweiterung durch Ports)

## Wie ist ein TCP Paket aufgebaut?

* Header, Flags, Pruefsumme
* Flags (URG, ACK, PSH, RST, SYN, FIN)

## Welche Zustaende gibt es im TCP Zustandsautomat?

* TCB = Transmissin Control Block (Datenerhaltung: Status pro Verbindung)
* Anzeige: netstat --ip
* Verbindungsaufbau 3-Way-Handshake 

## Was ist ein SYN Flood Attack?

* Angriff auf Layer 4 des TCP
* Idee: Ueberlastung des Rechners durch vielfache parallele Intitiierung des 3-Way-Handshakes druch mehrere SYN-Segmente, erzeugt Half Open Connections
* SYN = Synchronize Flag zur Initiierung eines Verbindungsaufbaus
* Oft mit DDoS

## Was sind Moeglichkeiten, SYN Flood Attacken abzuwehren?

* SYN-Cookies: Server schickt SYN-ACK und loescht TCB
* TCB Speicher erweitern
* Recycling von alten Speichereintraegen
* ERhoehung der Redundanzen durch Anycastadressierung und Multiplikation von Diensten

## Was sind zum Aufdecken von Luecken in Software?

Fehler: Logik Fehler, Speicherlecks, Formatstring-Angriffe, Pufferueberlaeufe

Methode:
* Statische Codeanalyse
* Dynamische Codeanalyse
* Fuzzing

## Wie funktioniert die Programmausfuehrung auf x86-Systemen?

1. Fetch: The x86 instruction pointer (IP) is used to fetch the next instruction from memory. The instruction is then loaded into the instruction register (IR).
2. Decode: The instruction in the IR is decoded by the instruction decoder, which determines what operation the instruction represents.
3. Operand Fetch: The instruction decoder fetches the operands required for the operation, such as the source and destination registers, from the register file.
4. Execution: The execution unit performs the operation specified by the instruction, using the operands from the register file.
5. Writeback: The result of the operation is written back to the register file, or to memory if the result is to be stored there.
6. Repeat: The process is repeated for each instruction in the program, until the end of the program is reached or an error occurs.

## Was sind Schutzmassnahmen gegen Bufferoverflow?

ASLR = Address Space Layout Randomization

* Adressbereiche fuer Programme werden zufaellig zugewiesen, daher nur schwer vorhersehbar

## Was ist das Prinzip von Stack Canaries?

Technik gegen Bufferoverflow-Angriffe

1. Ablage von eindeutigem Wert (Canary) vor der Return Adresse einer Funktion auf dem Stack
2. Bei Return wird der Canary-Wert überprüft, Canary anders => Es gab Bufferoverflow (Programm wird beendet)

## Was ist Heap Spraying?

* Methode fuer clientseitige Angriffe gegen Webbrowser
* Schadcode: Sehr grosser NOP-Block (Landezone) + Code
* Verhaeltnis 100:1
* Solaneg in dem NOP-Block gelandet wird, wird der Schadcode ausgefuehrt
* Spraying: Platzierung von sehr vielen Instanzen des Schadcodes ueber grosse Speicherbereiche hinweg, dadruch grosse Wahrscheinlichkeit, auf einem NOP-Sled zu laden

Ablauf:

1. Angreifer betreibt Webseite, die mit JS-Code Heap Spraying im Browser des Ziels betreibt
2. Dann wird eine Schwachstelle im Browser ausgenutzt

## Was ist der Domain Name Service?

* Moeglichkeit, Namen mit IP Adressen zu verknuepfen
* Hierarchischer Dienst fuer Namensgebung, Namensaufloesung (Forward Lookup), IP-Aufloesung (Reverse Lookup)
* Client/Server Anwendung mit serverseitiger Cache-Funktionalitaet
* Namensaufloesung erfolgt entsprechend hierarchisch von der Wurzel

## Was ist ein Fully Qualified Domain Name (FQDN)?

Verkettung aller Labels einer Domaene 

## Was macht ein DNS Server?

DNS Server verwaltet 2 Datenbanken:

* Forward-Zone Datenbank (Domainnamen -> IP-Adresseen)
* Reverse-Zone Datenbank (umgekehrt)
* Keine Ueberpruefung der Konsistenz der Datenbaenke

* DNS-Anfrage wird an Port 53 des DNS-Servers gesendet
* basiert auf unzuverlaessigem UDP (unbeantwortete Anfragen werden wiederholt)

## Wie kann man mit DNS Domainnamen oder IP-Adressen uebersetzen?

* nslookup

## Wie funktioniert eine DNS Abfrage?

1. Anfrage an Server
2. Falls IP-Adresse im Cache fertig, sonst rekursiv weiter suchen

## Wie wird CIA bei DNS gewaehrleistet?

* Confidentiality: Nicht wichtig, das es um das verbreiten von Information geht
* Integrity: Sicherung der Datenintegritaet sehr wichtig (DNS Spoofing, Umleitung auf Systeme des Angreifers)
* Availablity: DNS-Infrastruktur wichtig fuer fast alle Internet Kommunikation

## Was gibt es fuer Angriffe auf die DNS Infrastruktur?

* Angriffe auf Infrastruktur des Anbieters
* Angriff auf TLD-Betreiber
* Angriff auf Netz des Clients
* Angriff auf Daten im Internet

## Was ist DNS Spoofing?

* Idee: Veraernderung eines DNS-Eintrages um Opfer an komprimitierten Server/Dienst zu senden
* Manipulation der Hosts-Datei eines Rechners durch Malware/Bots

## Was ist klassisches DNS Spoofing?

zB ARP Cache Poisoning (MITM Angriff)

* Umlenken der DNS-Anfrage an DNS-Server des Angreifers oder kompromitierte DNS-Server
  * Alternative 1: Manipulation des Routings zwischen DNS Serverns
  * Alternative 2: Umleitung und Manipulation des Antwortpakets (Angreifer muss im gleichen L2-Netz wie der lokale DNS Server des Opfers)

## Was sind die Schritte bei klassischem DNS Spoofing?

1. Opfer fragt nach Domainnameaufloesung bei DNS Server
2. Angreifer lauscht nach Aufloesung
3. Angreifer leitet Antwort um und manipuliert aufgeloeste IP-Adresse

## Was ist DNS Cache Poisoning/DNS Cache Pollution?

Manipulation des (einzelnen) DNS Caches durch Flutung von Antworten mit Erraten der korrekten TXID

* Layer 3 Zugriff
* Einschraenkung: Angriff zum richtigen Zeitpunkt, richtiger UDP Quellports, richtige TXID

## Was sind die Schritte beim DNS Cache Poisoning?

1. Opfer fragt nach Domainnameaufloesung bei DNS Server
2. DNS Server loest auf und schicht Antwort an ersten DNS Server
3. Angreifer fuehrt massiv paralleles Erraten der TXID durch
4. DNS Server cachet manipulierte IP-Adresse
5. Opfer erhaelt die IP-Adresse des Angreifers

## Wie funkioniert ein DNS Angriff mit Kaminsky Methode?

1. Sending a query: The attacker first sends a query to a target DNS resolver for a specific domain name.
2. Forging responses: The attacker then sends a large number of forged responses to the target DNS resolver, claiming to be the authoritative DNS server for the same domain name. These responses contain incorrect mapping information, such as mapping a well-known domain name to the IP address of a malicious server.
3. Overwriting cached information: The target DNS resolver, due to the way it was designed to handle multiple responses to the same query, may cache the incorrect mapping information provided by the attacker.
4. Redirecting users: When a client computer sends a request to the target DNS resolver for the domain name, the resolver will return the incorrect IP address provided by the attacker, causing the client to be redirected to the attacker's malicious server.


## Was sind Schutzmechanismen gegen DNS-Spoofing?

* ARP Cache Poisoning Detektions/Schutzwerkzeuge (IP->MAC Aenderungen werden beobachtet)
* Implementierung von zertifikatsbasierten Anwendungen (extern signiert)
* Nicht sequentielle Generierung der TXID
* Einsat von verschluesselter Kommunikation zwischen Client und DNS-Server
* Implementierung von DDNSec Standard (vergl. mit einer PKI)

## Was ist DNSec?

* Ziel: Authentizitaet und Interitaet von DNS-Eintraegen
* Abwehr DNS-Cache Poisoning
* Zwei Schluesselpaare pro Domaene:
  * Key-Signing-Key: Bestehend aus einem privaten und oeffentlichen Schluessel, wird zum signieren anderer Schluessel verwendet
  * Zone-signing-Key: Besteht aus einem privaten und oeffentlichen Schluessel, kann autonom von den lokalen Administratoren einer Domaene verwaltet werden

## Wie funktioniert DNSSec?

1. Key Generation: The first step is to generate a set of public and private keys. The public keys are stored in the DNS zone, while the private keys are kept secret.
2. Signing: The domain owner uses their private key to sign the DNS records, creating a cryptographic signature for each record. The signed records are then published in the DNS zone.
3. Resolution: When a client wants to look up a DNS record, it first queries the DNSSec-enabled DNS server. The server returns the requested record along with its digital signature.
4. Validation: The client then uses the public key stored in the DNS zone to verify the signature. If the signature is valid, the client knows that the DNS record has not been tampered with and can be trusted.
5. Cache: The client caches the validated DNS record and its signature, so it doesn't have to go through the validation process every time it needs to look up the same record.
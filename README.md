# Review Questions

## Kapitel 1

1. Was versteht man unter Safety, was unter Security?

   * Safety: Schutz vor Verlust von Daten, etwa durch Hardwarefehler
   * Security: Schutz vor unautorisiertem Zugriff, etwa auf private Informationen

2. Geben Sie Beispiele!

   * Safety: Backups, Checksummen
   * Security: Verschlüsselung, Anti-Virus

3. Nennen Sie die sieben Ziele der Netzwerksicherheit, die Sie in der Schule kennengelernt haben, und erläutern Sie diese!

   1. Vertraulichkeit: Schutz von Informationen vor unbefugtem Zugriff oder Offenlegung. Dies beinhaltet die Verschlüsselung von Daten und die Implementierung von Zugriffskontrollmechanismen.
   2. Integrität: Sicherstellen, dass Daten während der Übertragung oder Speicherung nicht unbemerkt verändert oder manipuliert werden. Hierbei kommen Integritätsprüfungen, wie beispielsweise kryptografische Hash-Funktionen, zum Einsatz.
   3. Verfügbarkeit: Gewährleistung, dass Netzwerkdienste und -ressourcen zuverlässig und kontinuierlich verfügbar sind. Dazu gehören Maßnahmen zur Verhinderung von Ausfällen, DDoS-Schutz (Distributed Denial of Service) und die Implementierung von Notfallwiederherstellungsplänen.
   4. Authentifizierung: Überprüfung der Identität von Benutzern, Geräten oder Systemen, um sicherzustellen, dass nur autorisierte Personen oder Entitäten auf das Netzwerk zugreifen können. Dies kann durch Passwörter, biometrische Merkmale oder andere Authentifizierungsmethoden erfolgen.
   5. Autorisierung: Bestimmung der Zugriffsrechte und Berechtigungen für authentifizierte Benutzer. Dadurch wird sichergestellt, dass Benutzer nur auf die ihnen zugewiesenen Ressourcen zugreifen können.
   6. Verfügbarkeit: Schutz des Netzwerks und der Ressourcen vor Bedrohungen wie Viren, Malware, Würmern oder Hackern. Dies erfordert die Implementierung von Sicherheitsmechanismen wie Firewalls, Intrusion-Detection-Systemen und Antivirenprogrammen.
   7. Überwachung und Protokollierung: Kontinuierliche Überwachung des Netzwerks, um Sicherheitsvorfälle zu erkennen und darauf zu reagieren. Die Protokollierung von Netzwerkaktivitäten ermöglicht eine spätere Analyse von Sicherheitsvorfällen und unterstützt forensische Untersuchungen.

4. Was besagt Kerckhoff’s Principle?

    Die Sicherheit eines Systems sollte nicht auf der Geheimhaltung des Systems, sondern der des Schlüssels obliegen. Der Gegner soll das System kennen.

5. Was wäre das Gegenteil davon?

    Wenn das System nur als sicher betrachtet wird, weil es versteckt ist.

6. Was besagt Scheier’s Law?

    Jeder kann eine Verschlüsselung entwickelt, die man selbst nicht knacken kann. Das bedeutet nicht, dass diese sicher ist. Ein solcher Verschlüsselungsalgorithmus sollte öffentlich sein und von Experten überprüft werden.

7. Was folgt daraus für Sicherheitalgorithmen in Software?

    Die Folge daraus ist, dass keine eigenen Algorithmen entwickelt, sondern bestehende verwendet werden sollten, die schon überprüft wurden.

8. Was ist ein Attacker Model?

   * Umgebung des Angreifers
   * Potenzial für den Angreifer
   * Vorteile für den Angreifer

9. Wozu wird ein Attacker Model benötigt?

    Ein _Attacker Model_ wird benötigt, um die Sicherheit von interaktiven Protokollen zu bestimmen. Man analysiert, welche Möglichkeiten ein Angreifer hat die Verschlüsselung zu knacken, wenn ihm bestimmte Möglichkeiten gegeben werden.

10. Was ist das Dolev-Yao Attacker Model? Wozu ist demnach ein Angreifer in der Lage?

    Im Dolev-Yao Attacker Model geht man von bestimmten Bedingungen und einer bestimmten Umgebung aus, in denen sich ein Angreifer befindet, um die Verschlüsselung eines Protokolls zu knacken:

    * Umgebung: ein Netzwerk, das aus einer bestimmten Anzahl an Teilnehmern besteht. Alle Teilnehmer sind miteinander vernetzt und tauschen Nachrichten aus. Weitere Teilnehmer können zu jedem Zeitpunkt dazukommen und müssen nicht autorisiert sein.
    * Angreifer: der Angreifer ist ein Teilnehmer des Netzwerks, der Nachrichten senden, empfangen, abfangen und manipulieren und als ein anderer Teilnehmer senden kann. Der Angreifer kann nicht die Sicherheit knacken.

    Ein Protokoll kann nach diesem Angreifermodell als sicher betrachtet werden, wenn der Angreifer keine Nachrichten 1.1.unentdeckt1.1. manipulieren kann.

11. Wofür stehen Alice, Bob, Trudy und Eve in der Literatur?

    1. Alice und Bob: normale Gesprächspartner, die sicher Nachrichten austauschen wollen.
    2. Trudy: steht für Intruder und kann Nachrichten abfangen, löschen und hinzufügen.
    3. Eve: steht für Eavesdropper und kann Nachrichten (passiv) mitlesen.

12. Was sind entsprechende Entitäten in der Realität?

    1. Alice und Bob: Webbrowser/Server, Client/Server, DNS-Server, Router
    2. Trudy und Eve: Angreifer, die eine Verschlüsselung knacken wollen

13. Erklären Sie Verschlüsselung formal mithilfe von Funktionen und erklären Sie die verwendeten
    Parameter!

    $E(K_{e}, m) = c$

    * $E$ ist die Verschlüsselungsfunktion
    *. $K$ ist der Schlüssel. Man unterscheidet zwischen symmetrischer $K_{e} = K_{d}$ und asymmetrischer Verschlüsselung, bei der zwei Schlüssel gibt, für die meist $K_{e} = K^{+}$ und $K_{d} = K^{-}$ gilt.
    * $m$ ist die Klartextnachricht.
    * $c$ ist der verschlüsselte Text. Die Abkürzung steht für _Cipher_.

14. Was ist ein XOR Cipher?

    Bei einem XOR Cipher wird die Klartextnachricht $m$ mithilfe eines Schlüssels $K$ mittels XOR-Operation verschlüsselt: $m \oplus m = c$

15. Was bedeutet Interception?

    Interception passiert, wenn Nachrichten abgefangen werden. Das kann physisch, durch Veränderung der Verkabelung, oder logisch, durch Rekonfiguration von DNS oder ARP erfolgen.

16. Was bedeutet Eavesdropping?

    Eavesdropping ist das Abhören von Nachrichten. Das kann physisch, durch _Wiretapping_ oder Mitlesen des Netzwerkverkehrs, oder logisch durch die Umleitung des Verkehrs erfolgen.

17. Warum nennt man es einen passiven Angriff?

    Eavesdropping ist passiv, da der Angreifer den Datenverkehr nicht manipuliert.

18. Wie können Angreifer an die Daten herankommen?

    1. physisch: _Wiretapping_ oder Mitlesen des Netzwerkverkehrs.
    2. logisch: Umleitung des Verkehrs.

19. Wie kann Eavesdropping verhindert werden?

    Verschlüsselung der Nachrichten

20. Was versteht man unter lawful interception?

    "Lawful Interception (LI) ist ein Sicherheitsverfahren, bei dem ein Diensteanbieter oder Netzbetreiber die abgefangene Kommunikation von Privatpersonen oder Organisationen sammelt und den Strafverfolgungsbehörden zur Verfügung stellt."

21. Was ist eine Replay Attack?

    Eine Replay Attacke ist, wenn ein Angreifer eine Nachricht mitliest, kopiert und mehrmals an einen Empfänger sendet.

22. Wie können Replay Attacks verhindert werden?

    Mithilfe von Sequenznummern. Wenn dieselbe Nachricht mit derselben Sequenznummer gesendet wird, handelt es sich um dieselbe Nachricht und sollte trotz mehrfacher Wiederholungen als eine Nachricht behandelt werden.

23. Was ist eine Modification Attack?

    Eine Modification Attack ist eine aktive Attacke, bei der Angreifer Nachrichtenpakete bspw. modifiziert, umleitet und Schleifen erzeugt

24. Geben Sie Beispiele an!

    * Blackmail Attacke: einen scheinbar guten Knoten als schlecht markieren, indem er übersprungen wird

25. Erläutern Sie Gegenmaßnahmen!

    * Verschlüsselung: Indem der Nachrichteninhalt verschlüsselt wird, kann er nur vom vorgesehenen Empfänger entschlüsselt und gelesen werden. Durch die Verschlüsselung ist eine Modifikation ohne den Entschlüsselungsschlüssel nicht möglich und ein Angriff erschwert.
    * Signaturen: Durch Signaturen kann sichergestellt werden, dass die Nachricht vom vorgesehenen Sender gesendet wurde.

26. Was ist eine Impersonation Attack? Wie kann sie aussehen?

    Bei einer Impersonation Attacke gibt sich ein Angreifer als jemand anderes aus. Das kann in Form von IP- oder MAC-Adressen spoofing gelingen.

27. Was ist eine MitM attack?

    Ein besonderer Fall der Impersonation Attacke ist die Man-in-the-Middle Attacke, bei der sich ein Angreifer zwischen zwei kommunizierende Parteien einschleust, den Verkehr mitliest, manipuliert und versucht an sensible Informationen zu gelangen.

28. Wie kann sie verhindert werden?

    * Verschlüsselung: verschlüsselte Nachrichten können nur dem entsprechenden Schlüssel, den idealerweise nur der vorgesehene Empfänger besitzt, entschlüsselt werden.
    * Signaturen: Signaturen stellen sicher, dass Nachrichten nur vom erwarteten Sender gesendet wurden.

29. Was ist eine DoS attack?

    Denial-out-of-Service Attacken zielen darauf ein System durch eine Vielzahl von Anfragen zu beeinträchten bishin zum vollständigen Absturz.

30. Was bedeutet DDos?

    Distributed-DoS Attacken sind verteilte Attacken, bei denen meist ein Netzwerk aus mehreren tausend Rechnern versuchen ein System anzugreifen. Diese Rechner sind dann meist ungewollt Teil eines Bot-Netzes.

31. Geben Sie ein Beispiel für eine DoS attack an!

    SYN-Flooding: TCP Handshakes, bei denen der Angreifer die Antwortpakete nicht beantwortet, sodass der Server auf die Antwortpakete wartet und keine weiteren Verbindungen mehr aufbauen kann.

32. Was versteht man unter einer Amplified DDoS Attack?

    Amplified DDoS Attacken sind DDoS Attacken, bei denen der Angreifer die Antwortpakete so manipuliert, dass sie größer sind als die Anfragepakete. Dadurch wird der Server mit einer Vielzahl von großen Paketen überflutet. Die Leitung des Servers ist in diesen Fällen auch so überlastet, dass der Server nicht mehr nach Außen kommunizieren kann.

33. Beschreiben Sie wie eine NTP DDoS Attack funktioniert!

    NTP wird für die Zeitsynchronisierung verwendet. Das Verhältnis zwischen Anfragen:Antwort-Größe ist 1:20 bis 1:200. Schlecht konfigurierte NTP-Server können für Amplified DDoS Attacken verwendet werden, indem der Angreifer eine Anfrage mit einer gefälschten Absenderadresse an einen NTP-Server sendet. Der NTP-Server antwortet mit einer großen Antwort an die gefälschte Adresse.

34. Wie kann man dem on premise bzw. in der cloud begegnen?

    * On-premise: der Uplink muss größer sein, als die Angriffsbandbreite.
    * Cloud: der Provider muss die Angriffsbandbreite abwehren können.

35. Welche zwei Ansätze gibt es, um Verschlüsselung zu brechen?

    * Kryptoanalyse: Verschlüsselung wird gebrochen, indem der Angreifer die Verschlüsselungsmethode analysiert und versucht den Schlüssel zu finden. Bspw. statistische Kryptoanalyse, Known-Plaintext Attacken, Chosen-Plaintext Attacken.
    * Schlüsselraum-Suche: Verschlüsselung wird gebrochen, indem der Angreifer alle möglichen Schlüssel ausprobiert. Bspw. Bruteforce Attacken, Dictionary Attacken.

36. Nennen sie zwei Arten von Angriffen, um Schlüssel herauszufinden!

    * Bruteforce Attacken
    * Dictionary Attacken

37. Was versteht man unter Kryptoanalyse?

    Bei der Kryptoanalyse wendet man Mathematik und statistische Analysen an, um die Verschlüsselung kryptographischer Systeme zu knacken und Zugrif auf den Inhalt verschlüsselter Nachrichten zu erhalten.

38. Welche drei unterschiedlichen Arten von Kryptoanalyse gibt es?

    * Ciphertext-only: Es liegt nur der Ciphertext vor.
    * Known-plaintext: Es liegen mehrere Klartext-Ciphertext Paare vor, die mit dem System verschlüsselt wurden.
    * Choosen-plaintext: Es dürfen beliebige Klartextnachrichten mit dem System verschlüsselt werden.

39. Was sind side channel attacks?

    Attacken, die über einen unsicheren Seitenkanal passieren. Ein Seitenkanal kann etwa die Temperatur eines Systems oder dessen Stromverbrauch sein, über den Annahmen über das System getroffen werden können, etwa, wie lang der Schlüssel ist, wie lang die verschlüsselte Nachricht ist,oder, welche Verschlüsselung verwendet wird.

40. Wie funktioniert eine brute-force attack auf Passwörter bzw. auf Verschlüsselung?

    * Passwort-Attacke: Der Benutzername ist bekannt. Es werden solange zufällige Passwörter generiert, bis das richtige gefunden wurde.
    * Encryption-Key-Attacke: Es werden so lange Schlüssel generiert und eine verschlüsselte Nachricht damit entschlüsselt, bis der Inhalt der Nachricht plausibel ist.

41. Wovon hängen die Erfolgschancen von brute-force attacks vorwiegend ab?

    Von der Schlüsselgröße. Der Schlüsselraum wächst exponentiell mit der Schlüssellänge.

42. Was ist eine dictionary attack?

    Anstelle zufällige Passwörter generieren, wird versucht eine Verschlüsselung mit einer Liste häufig verwendeter Passwörter zu knacken.

43. Wie funktioniert statistische Kryptoanalyse mit cyphertext-only? Was ist eine Voraussetzung dafür?

    Bei der statistischen Kryptoanalyse wird etwa die Frequenz der Buchstaben in einer Cipher mit einer bekannten Frequenztabelle einer Sprache abgeglichen. Die Voraussetzung dafür ist, dass die Verschlüsselung nicht den Klartext 1:1 abbildet, sondern etwa durch Substitution oder XOR verschlüsselt.

44. Beschreiben Sie, wie eine Known-Plaintext Attack funktioniert?

    XOR Cipher:
    * $m = 010001101$
    * $c = 111011111$
  
    * $m \oplus c = k$
    * $010001101 \oplus 111011111 = 101010010$

45. Warum ist eine Chosen-Plaintext Attack wirkungsvoller?

    Der Angreifer kann beliebig viele Nachrichten verschlüsseln und die erhaltenen Cipher analysieren. Lässt sich mittels statistischer Kryptoanalyse ein Muster erkennen, kann evtl. die Verschlüsselung geknackt werden.

46. Nennen Sie einen Satz mit 26 verschiedenen Buchstaben!

    "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern"

47. Was nutzen Side Channel Attacks aus? Nennen Sie Beispiele für Side Channel Attacks!

    Side Channel Attacks nutzen Informationen, die über einen unsicheren Seitenkanal verfügbar sind. Beispiele sind etwa die Temperatur eines Systems oder dessen Stromverbrauch.

## Kapitel 2

1. Nennen Sie eine allgemeine Notation für Verschlüsselung!

    $$c = E(K_e, m)$$

2. Was sind symmetrische und asymmetrische Kryptografie?

    Bei der 1.1.symmetrischen Kryptografie1.1. werden Texte mit einem symmetrischen Schlüssel verschlüsselt. Es kann sich dabei um den gleichen Schlüssel $K$ handeln, mit dem ein Text ver- und wieder entschlüsselt wird, oder, $K_d$ kann aus $K_e$ errechnet werden.
    Beispiele hierfür sind _One-time Pads}, \textit{Stream Cipher}, \textit{Block Cipher_.

    Bei der 1.1.asymmetrischen Kryptografie} gibt es zwei Schlüssel $K_e$ und $K_d$, wobei sich $K_d$ nicht aus $K_e$ errechnen lässt. Meistens ist $K_e$ öffentlich, während der $K_d$ privat bleiben muss, damit die Nachricht nicht von jedem entschlüsselt werden kann. Ein Beispiel hierfür ist \textbf{RSA1.1..

3. Was benötigt symmetrische Kryptografie, ehe sie angewendet werden kann?

    Für symmetrische Kryptografie muss der geteilte Schlüssel $K_s$ über einen sicheren Kanal ausgetauscht werden.

4. Was sind one-time pads?

    One-time Pads sind Schlüssel, die unter idealen Bedingungen _Perfect Privacy_  bieten und damit nicht knackbar sind. Mit ihnen werden Nachrichten mittels XOR-Operation verschlüsselt.
    Die Bedingungen für Perfect Privacy sind:

        1. zufälliger Schlüssel $K$
        1. $len(K) \geq len(m)$
        1. Schlüssel $K$ darf nur einmal genutzt werden

5. Was sind Stream Ciphers?

    Stream Cipher sind Key-Stream Generatoren, die einen Schlüssel $K$ bestimmter Länge um die Länger einer Nachricht $m$ expandieren. Mit diesem Key-Stream kann eine Nachricht bitweise mittels XOR Operation verschlüsselt werden.
    Stream Ciphers arbeiten mit Bits, während _Block Ciphers_ mit Blöcken arbeiten.

6. Was sind Block Ciphers?

    Mit Block Ciphers werden Nachrichten in einzelne, gleich große Blöcke unterteilt. Die Nachrichtenblöcke werden dann blockweise auf verschlüsselte Blöcke abgebildet.

7. Was ist ein Transposition Cipher?

    In einem Transposition Cipher werden nur die Positionen der einzelnen Buchstaben verändert.

8. Wie funktioniert ein Skytale? Was ist der Schlüssel?

    Ein Skytale ist ein Stab, der als Schlüssel fungiert, und um den ein Band, auf dem ein Text steht, gewickelt wird. Ohne den Stab sind die Buchstaben auf dem Band zusammengewürfelt. Erst durch das Wickeln um den Stab wird der Text erkenntlich gemacht.

9. Was ist ein Substitution Cipher? Was ist der Schüssel?

    Bei einem Substitution Cipher wird ein Buchstabe mit einem anderen substituiert. Der Schlüssel ist dabei die eindeutige Abbildung, von einem Buchstaben auf einen anderen. Das heißt, ein Buchstabe kann nicht auf zwei Buchstaben abgebildet werden, wodurch die eben die Eindeutigkeit nicht mehr gegeben wäre. Der Substitution Cipher ist ein _monoalphabetischer Cipher_.

10. Was ist Caesar’s Cipher? Was ist der Schlüssel?

    Der Caesar’s Cipher ist ein spezieller Fall eines monoalphabetischen Ciphers, bei dem alle Buchstaben in einem Text um einen bestimmten Schlüssel $K \in [0, 25]$ verschoben werden.
    Wenn der Schlüssel $K = 13$, spricht man auch von Caesar-ROT1.

    "Network Security ist spannend" wird bei $K = 13$ zu "arGJBEx frpHEvGL vFG FCnAArAq", wobei dann N auf A, E auf R usw. abgebildet werden.

11. Was ist Polyalphabetic Substitution? Was ist der Schlüssel?

    Bei der polyalphabetischen Substitution werden mehrere Alphabete $n=3, M_1, M_3, M_7$ verwendet, um einen Text $m$ zu verschlüsseln. Dabei bestimmt die Position des zu substituierenden Buchstabens, welches Alphabet verwendet werden soll. Ein Doppelbuchstabe kann damit zu zwei verschiedenen Buchstaben substituiert werden, je nachdem, in welchem Alphabet sich dieser befindet. Da meist $len(m) \geq n$, rotieren die Alphabete in derselben Reihenfolge durch.

12. Nennen Sie einen bekannten Polyalphabetic Cipher!

    Ein bekanntes Beispiel ist der \href{<https://en.wikipedia.org/wiki/Vigenère_cipher}{Vigenère> cipher}.

13. Was ist der Unterschied zwischen einem RNG und einem echten PRNG?

    Der 1.1.R}andom \textbf{N}umber \textbf{G1.1.enerator (RNG) generiert echte Zufallszahlen auf der Basis von physikalischen Prozessen, wie Rauschen. Er ist nicht-deterministisch und unvorhersehbar.

    Der 1.1.P}seudo \textbf{R}andom \textbf{N}umber \textbf{G1.1.enerator (PRNG) generiert statistisch zufällige Zahlen auf Basis eines _Seeds_. Bleibt der Seed gleich, wird immer dieselbe Folge von Zufallszahlen generiert. Dieser Generator ist nicht kryptografisch sicher, da sich die Folge beobachten und vorhersagen lässt.

14. Was ist ein statistically secure PRNG?

    Ein statistisch sicherer PRNG unterscheidet sich vom PRNG insoweit, als, dass er zwar durch den Seed auch deterministisch, aber nicht vorhersehbar ist.

15. Wie funktioniert ein Stream Cipher? Beschreiben Sie seine Arbeitsweise mit geeigneter Notation! Was ist der Schlüssel?

    Ein Stream Cipher ist ein PRNG, bei dem der Seed als Schlüssel fungiert und bei dem eine Nachricht $m$ bitweise per XOR-Operation mit dem Keystream $ks$ verschlüsselt wird.

        1. Verschlüsselung: $c(i) = ks(i) \oplus m(i)$.
        2. Entschlüsselung: $m(i) = ks(i) \oplus c(i)$

    Der Schlüssel ist symmetrisch.

16. Nennen Sie Vorteile von Stream Ciphers!

        1. Verschlüsselung von einem Bit auf einmal. Das heißt, der Sender kann direkt verschlüsseln, ohne auf ganze Blöcke zu warten, wie es beim Block Cipher der Fall ist. Stream Cipher eignen sich damit für Realzeitanwendungen.
        2. Singlebit-Fehler im Ciphertext $c$ führen zu Singlebit-Fehlern im Klartext $m$ und können mithilfe der _Forward Error Correction (FEC)_ korrigiert werden.

17. Wofür steht RC4?

    \enquote{Ron's Cipher 4} ist ein (Byte-orientierter) Stream Cipher.

18. Was ist ein Vorteil von RC4?

        1. variable Schlüssellänge,
        2. performant,
        3. einfacher Algorithmus, der sich damit auch einfach implementieren lässt. Das führt wiederum zur Minimierung von Fehlern bei der Implementierung und der Verminderung von _Side-Channel Attacken_.

19. Was ist _Key Scheduling_ in RC4? Wie funktioniert es in Grundzügen?

    Key Scheduling dient dazu eine Substitutionstabelle

20. Wie funktioniert die RC4 Verschlüsselung in Grundzügen? Wie viele zufällige Bits werden dabei auf einmal erzeugt? Auf welcher internen Datenstruktur arbeitet RC4? Wie wird diese im Laufe
der Verschlüsselung verändert?

    RC4 besteht aus zwei Schritten:

        1. Key Scheduling: Zustand initialisieren
        2. Verschlüsselung: Keystream generieren und den Klartext-Stream mit dem Keystream per XOR-Operation verschlüsseln

    Es werden $m$-viele Bits erzeugt, wobei $m$ die Länge der Nachricht, die verschlüsselt werden soll, ist. RC4 baut auf einer Substitutions-Box, kurz _S-Box_. Diese Struktur wird so verändert, dass Buchstaben mit den Indexen $i = (i + 1) (mod 256)$ und $j = (j + S[i]) (mod 256)$ miteinander vertauscht werden.

21. Erläutern Sie T[] und S[], wofür sie verwendet werden, und wie der Schlüssel verwendet wird!

    $S$[] ist die S-Box mit einer Länge von 255 Bytes. $T$[] ist ein temporäres Array, das verwendet wird, um die S-Box zu befüllen. Am Anfang ist die S-Box nur mit den Werten von 0 bis 255 befüllt. In $T$ wird der Schlüssel $K$ mehrere Male hintereinander gereiht, da der Schlüssel $K$ kleiner als die maximale Länge von $255 B = 2048 Bits$ sein kann. Die S-Box wird dann mithilfe von T, das potenziell mehrere Kopien des Schlüssels enthält, permutiert.

22. Wofür wird RC4 verwendet?

        1. WiFi: WEP, WPA, WPA2
        2. Microsoft Point-to-Point Encryption Protocol
        3. Remote Desktop Protocol

23. Ist die Verwendung von RC4 empfehlenswert?

    Nein, da RC4 heutzutage als unsicher betrachtet wird. Anfangs wurde RC4 geheim gehalten, um Sicherheit durch die Geheimhaltung des Algorithmus zu garantieren.

24. Wie funktioniert Salsa20 in Grundzügen? Wie viele zufällige Bits werden dabei auf einmal erzeugt?
Auf welcher internen Datenstruktur arbeitet Salsa20? Wie wird diese im Laufe der
Verschlüsselung verändert?

25. Was ist ChaCha? Wie unterscheidet es sich von Salsa20? Was ist der Vorteil?

26. Wo wird ChaCha verwendet?

27. Welche Stream Ciphers kennen Sie noch? Welche davon sind noch empfehlenswert?

28. Wie funktioniert ein Block Cipher prinzipiell?

29. Was ist das Problem bei einer naiven Implementierung und wie wird das Problem ge-
löst?

30. Was ist ein Feistel Cipher? Wie funktioniert er? Welche Methoden basieren auf Feistel
Ciphers?

31. Was heißt DES? Was heißt NIST? Was heißt FIPS?

32. Wie groß ist die Block Size bei DES, wie groß der Schlüssel? Was sind round keys?

33. Warum benötigt DES einen Key Schedule? Was macht er?

34. Was ist eine S-box? Was ist eine P-box?

35. Wie funktioniert die Entschlüsselung mit DES?

36. Was sind Schwächen von DES?

37. Was ist Triple-DES (3DES)? Was ist seine key size?

38. Warum wird nicht 2DES verwendet?

39. Wird 3DES verwendet? Welches Problem von DES wird durch 3DES nicht gelöst?

40. Was ist ein weiterer Nachteil von 3DES gegenüber neueren Ciphers?
41. Was bedeutet AES? Welche Block Size hat er? Welche Key Sizes unterstützt er?

42. Wie steht es mit der Performance von AES?

43. Wie funktioniert AES strukturell?

44. Wie geht der Schlüssel ein?

45. Warum benötigt man einen Key Scheduling Algorithm?

46. Warum werden Operation Modes für Block Ciphers verwendet?

47. Was heißt ECB und wie funktioniert es? Was sind seine Probleme?

48. Was heißt CBC und wie funktioniert es? Was sind seine Probleme?

49. Was heißt CTR und wie funktioniert es? Was sind seine Probleme?

50. Was bedeutet synchronous im Kontext von ciphers? Geben Sie zwei Beispiele an!

51. Was sind self-synchronization block ciphers?

52. Was heißt OFB und wie funktioniert es? Was sind seine Probleme?

53. Was heißt CFB und wie funktioniert es? Was sind seine Probleme?

54. Was ist eine Hash Funktion?

55. Geben Sie einfache Hashes an und diskutieren Sie deren Probleme im Kontext Krypto-
graphie!

56. Was ist für kryptografische Hashes essenziell?

57. Welche Arten von _Resistance_ kennen sie und was bedeuten sie?

58. Nennen Sie Synonyme für kryptografische Hashes!

59. Warum ist die Internet Checksumme kein guter Message Digest?

60. Was ist Ziel und Funktionsweise der Merkle-Damgard-Construction?

61. Warum benötigt man dafür einen IV? Warum benötigt man padding?

62. Was heißt MD5? Nach welchem Prinzip funktioniert MD5? Was ist seine Blockgröße? Wie groß ist seine Digest Sizes?

63. Ist MD5 noch sicher? Wofür kann er verwendet werden?

64. Was heißt SHA?

    SHA steht für 1.1.S}ecure \textbf{H}ash \textbf{A1.1.lgorithm.

65. Nach welchem Prinzip funktioniert SHA-1? Was ist seine Blockgröße? Was ist seine
Digest Size? Welche Attacke gibt es gegen SHA-1?

    SHA-1 ist eine Merkle-Damgard Konstruktion. Es gibt eine Blockgröße von 512 Bit und hat einen _Message Digest_ von 160 Bit. Der Message Digest ist ein Hash-Output.

    Gegen SHA-1 gibt es die 1.1.Collision-Attack1.1.. Das bedeutet, dass zwei verschiedene Inputs zum selben Output führen.

66. Was ist ein wesentlicher Unterschied zwischen SHA-1 und SHA-2? Welche Varianten gibt
es?

    SHA-2 produziert im Vergleich zu SHA-1 längere Digests.

67. Was ist SHA-3?

68. Was sind Message Authentication Codes? Was sind Synonyme?

69. Was ist das Problem bei Simpled Keyed Hashes?

70. Was ist HMAC und wie funktioniert es?

    HMAC steht für Keyed-1.1.H}ashing \textbf{M}essage \textbf{A}thentication \textbf{C1.1.ode und ist eine standardisierte Einweg-Hashfunktionen, die mit einem Schlüssel $k$ arbeitet, aber Hashes anstelle von Verschlüsselung verwendet.

    $t = H(k \oplus opad |H(k \oplus ipad|m))$

71. Was können Sie über seine Sicherheit aussagen?

72. Was ist CBC-MAC? Was ist ein Problem und eine Gegenmaßnahme?

73. Was ist Poly1305? Wie funktioniert es strukturell? Woher kommt sein Name?

74. Was bedeutet (Non-)Malleability? Geben Sie Beispiele an!

75. Was ist authenticated encryption? Was sind Ziele?

76. Was heißt AEAD und was ist damit gemeint? Wie funktioniert AEAD?

77. Was bedeuten MAC-and-encrypt, MAC-then-encrypt, Encrypt-then-MAC?

78. Diskutieren Sie die Sicherheit dieser Varianten!

79. Was heißt CCM? Was sind Vorteile? Wie funktioniert es? Wie funktioniert die AEAD
version? Wo wird CCM angewendet?

80. Was heißt GCM? Wie funktioniert es? Was sind seine Vorteile?

81. Was ist GMAC?

82. Was ist ChaCha20-Poly1305? Wie funktioniert es strukturell?

83. Was ist ein grundlegender Unterschied zwischen symmetrischer und asymmetrischer
Kryptografie?

84. Wie funktioniert Public Key Kryptografie?

85. Warum kann bei symmetrischer Kryptografie der Key, der zur Verschlüsselung genutzt wird, nicht veröffentlicht werden?

86. Was ist der kleinste gemeinsame Teiler von 169 und 221?

87. Was ist $\phi(50)$?

88. Was ist $\phi(5917)$? Hinweis: Die Primfaktoren von 5917 lauten 61 und     1.

89. Auf welchen Problemen der Zahlentheorie basiert die meiste asymmetrische Kryptografie?

90. Warum ist es im Kontext von RSA wichtig, dass d und e inverse zueinander sind?

91. Warum ist es schwer $\phi(n)$ zu berechnen, wenn nur n und e bekannt sind?

92. Was passiert beim vorgestellten Textbook RSA, wenn zweimal dieselbe Nachricht
verschlüsselt wird? Wie kann dieses Problem behoben werden?

93. Wie viele Multiplikationen sind notwendig, um 139118 zu berechnen, wenn der naive
Algorithmus aus der Schule verwendet wird?

94. Wie viele Multiplikationen sind notwendig mit dem Square-and-Multiply Algorithmus?

95. Leiten Sie aus den Eigenschaften einer Gruppe her, dass das neutrale Element in einer
Gruppe eindeutig ist!

96. Was ist ein Shared Secret? Wie bekommen beide Kommunikationspartner das shared secret?

97. Was ist non-repudiation?

98. Vergleiche RSA Signaturen mit dem normalen RSA Algorithmus!

99. Warum darf $k$ im Kontext von DSA nie mehrfach verwendet werden?

100. Wie funktioniert ElGamal?

    ElGamal wird mithilfe eines Beispiels erklärt, bei dem Alice eine Nachricht verschlüsselt an Bob senden möchte.

    Bei 1.1.ElGamal} wählt Alice ein zufälliges $y \in \{1, 2, ..., q - 1\}$, das nur einmal verwendet werden sollte, und berechnet mit $y$ und mit Bobs öffentlichem Schlüssel $h_{Bob}$ ein Shared Secret $s = h_{Bob}^y = (g^{x_{Bob}})^{y} = g^{xy}$. $h_{Bob} = g^{x_{Bob}}$ ist Bobs öffentlicher Schlüssel und $x_{Bob1.1.$ ist Bobs privater Schlüssel. Bei $g$ handelt es sich um einen Generator der Gruppe $G$.
    Mit $s$ kann Alice die Nachricht $m$ verschlüsseln, sodass sie $c_2 = m 1. s$ erhält. Zusätzlich zur Nachricht gibt sie $c_1 = g^{y}$ mit.
    Bob kann $m$ aus $m = (c_1)^{-x} 1. c_2 = ((g^{y})^{-x}) 1. (g^{xy} 1. m) = g^{-xy+xy} 1. m = g^{0} 1. m$ berechnen. Bob kennt $x$, da es sich um seinen privaten Schlüssel handelt.

    Beide Parteien können das Shared Secret $s$ ausrechnen. Alice rechnet $s = (g^{x_{Bob}})^{y} = g^{xy}$ aus und Bob rechnet $s = (g^{y})^{x_{Bob}} = g^{xy}$ aus.

101. Wozu wird der Diffie-Hellman Schlüsseltausch verwendet?

102. Was hat Diffie-Hellman mit ElGamal zu tun?

    Diffie-Hellmann und ElGamal beruhen beide auf dem Prinzip des _Shared Secrets_, das sich beide Parteien jeweils berechnen, und auf Operationen, die in einer Gruppe $G$ ausgeführt werden.

103. Was weiß ein Angreifer, der die gesamte Kommunikation eines Diffie-Hellmann Schlüsselaustausch mitgehört hat? Kann er damit das Shared Secret berechnen?

104. Definieren Sie Forward-secrecy! (Notwendig!)

    Forward secrecy

105. Angenommen ein Angreifer hört die Kommunikation eines DH Schlüsseltauschs ab. Zu
einem späteren Zeitpunkt nach dem Austausch findet der Angreifer die Private Keys für die
verwendeten Signaturen heraus. Warum nützt ihm dies nichts?

106. Machen Sie sich über die Folien hinaus mit elliptischen Kurven über R vertraut:
<https://andrea.corbellini.name/ecc/interactive/reals-add.html>.

107.   Machen Sie sich auch mit elliptischen Kurven über einem endlichen Körper <https://andrea.corbellini.name/ecc/interactive/modk-add.html>:

108.   Wie lautet die \enquote{Regel}, mit der aus klassischen Verfahren ein Verfahren mit
elliptischen Kurven konstruiert werden kann?

109.   Was sind die Vorteile von elliptischen Kurven gegenüber klassischer asymmetrischer Kryptografie?

110.   Welche Vorteile bietet Curve25519?

Zusatz: Informieren Sie sich über <https://en.wikipedia.org/wiki/Dual_EC_DRBG> über ein Verfahren mit elliptischen Kurven, dass diese Vorteile nicht bietet!

111. Welche Vorteile bieten symmetrische und asymmetrische Kryptografie?

112. Wie können die Vorteile von symmetrischer und asymmetrischer Kryptografie kombiniert
werden?

113. Vergleichen Sie die Sicherheit von RSA und ECC bei einer festen vorgegebenen Schlüssellänge!

114. Was können Quantencomputer effizient tun, was klassische Computer nicht können?

115. Ist symmetrische Kryptografie anfällig für Angriffe durch Quantencomputer?
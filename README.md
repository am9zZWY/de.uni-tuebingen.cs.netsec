# Review Questions

# Kapitel 1
\begin{enumerate}
    \item Was versteht man unter Safety, was unter Security?

        \begin{itemize}
            \item Safety: Sicherheit vor Ausfall
            \item Security: Schutz vor unautorisiertem Zugriff, etwa auf private Informationen
        \end{itemize}
    
    \item Geben Sie Beispiele!

        \begin{itemize}
            \item Safety: Backups, Checksummen
            \item Security: Verschlüsselung, Anti-Virus
        \end{itemize}
    
    \item Nennen Sie die sieben Ziele der Netzwerksicherheit, die Sie in der Schule kennengelernt haben, und erläutern Sie diese!

        \begin{enumerate}
            \item Vertraulichkeit: Schutz von Informationen vor unbefugtem Zugriff oder Offenlegung. Dies beinhaltet die Verschlüsselung von Daten und die Implementierung von Zugriffskontrollmechanismen.
            \item Integrität: Sicherstellen, dass Daten während der Übertragung oder Speicherung nicht unbemerkt verändert oder manipuliert werden. Hierbei kommen Integritätsprüfungen, wie beispielsweise kryptografische Hash-Funktionen, zum Einsatz.
            \item Verfügbarkeit: Gewährleistung, dass Netzwerkdienste und -ressourcen zuverlässig und kontinuierlich verfügbar sind. Dazu gehören Maßnahmen zur Verhinderung von Ausfällen, DDoS-Schutz (Distributed Denial of Service) und die Implementierung von Notfallwiederherstellungsplänen.
            \item Authentifizierung: Überprüfung der Identität von Benutzern, Geräten oder Systemen, um sicherzustellen, dass nur autorisierte Personen oder Entitäten auf das Netzwerk zugreifen können. Dies kann durch Passwörter, biometrische Merkmale oder andere Authentifizierungsmethoden erfolgen.
            \item Autorisierung: Bestimmung der Zugriffsrechte und Berechtigungen für authentifizierte Benutzer. Dadurch wird sichergestellt, dass Benutzer nur auf die ihnen zugewiesenen Ressourcen zugreifen können.
            \item Verfügbarkeit: Schutz des Netzwerks und der Ressourcen vor Bedrohungen wie Viren, Malware, Würmern oder Hackern. Dies erfordert die Implementierung von Sicherheitsmechanismen wie Firewalls, Intrusion-Detection-Systemen und Antivirenprogrammen.
            \item Überwachung und Protokollierung: Kontinuierliche Überwachung des Netzwerks, um Sicherheitsvorfälle zu erkennen und darauf zu reagieren. Die Protokollierung von Netzwerkaktivitäten ermöglicht eine spätere Analyse von Sicherheitsvorfällen und unterstützt forensische Untersuchungen.
        \end{enumerate}
    
    \item Was besagt Kerckhoff’s Principle?

        Die Sicherheit eines Systems sollte nicht auf der Geheimhaltung des Systems, sondern der des Schlüssels obliegen. Der Gegner soll das System kennen.
    
    \item Was wäre das Gegenteil davon?

        Wenn das System nur als sicher betrachtet wird, weil es versteckt ist.
    
    \item Was besagt Scheier’s Law?

        Jeder kann eine Verschlüsselung entwickelt, die man selbst nicht knacken kann. Das bedeutet nicht, dass diese sicher ist. Ein solcher Verschlüsselungsalgorithmus sollte öffentlich sein und von Experten überprüft werden.
    
    \item Was folgt daraus für Sicherheitalgorithmen in Software?

        Die Folge daraus ist, dass keine eigenen Algorithmen entwickelt, sondern bestehende verwendet werden sollten, die schon überprüft wurden.
    
    \item Was ist ein Attacker Model?

        \begin{itemize}
            \item Umgebung des Angreifers
            \item Potenzial für den Angreifer
            \item Vorteile für den Angreifer
        \end{itemize}
    
    \item Wozu wird ein Attacker Model benötigt?

        Ein \textit{Attacker Model} wird benötigt, um die Sicherheit von interaktiven Protokollen zu bestimmen. Man analysiert, welche Möglichkeiten ein Angreifer hat die Verschlüsselung zu knacken, wenn ihm bestimmte Möglichkeiten gegeben werden. 
    
    \item Was ist das Dolev-Yao Attacker Model? Wozu ist demnach ein Angreifer in der Lage?

        Im Dolev-Yao Attacker Model geht man von bestimmten Bedingungen und einer bestimmten Umgebung aus, in denen sich ein Angreifer befindet, um die Verschlüsselung eines Protokolls zu knacken:

        \begin{itemize}
            \item Umgebung: ein Netzwerk, das aus einer bestimmten Anzahl an Teilnehmern besteht. Alle Teilnehmer sind miteinander vernetzt und tauschen Nachrichten aus. Weitere Teilnehmer können zu jedem Zeitpunkt dazukommen und müssen nicht autorisiert sein.
            \item Angreifer: der Angreifer ist ein Teilnehmer des Netzwerks, der Nachrichten senden, empfangen, abfangen und manipulieren und als ein anderer Teilnehmer senden kann. Der Angreifer kann nicht die Sicherheit knacken.
        \end{itemize}

        Ein Protokoll kann nach diesem Angreifermodell als sicher betrachtet werden, wenn der Angreifer keine Nachrichten \textbf{unentdeckt} manipulieren kann.
    
    \item Wofür stehen Alice, Bob, Trudy und Eve in der Literatur?

        \begin{itemize}
            \item Alice und Bob: normale Gesprächspartner, die sicher Nachrichten austauschen wollen.
            \item Trudy: steht für Intruder und kann Nachrichten abfangen, löschen und hinzufügen.
            \item Eve: steht für Eavesdropper und kann Nachrichten (passiv) mitlesen.
        \end{itemize}
    
    \item Was sind entsprechende Entitäten in der Realität?

        \begin{itemize}
            \item Alice und Bob: Webbrowser/Server, Client/Server, DNS-Server, Router
            \item Trudy und Eve: Angreifer, die eine Verschlüsselung knacken wollen
        \end{itemize}
    
    \item Erklären Sie Verschlüsselung formal mithilfe von Funktionen und erklären Sie die verwendeten 
    Parameter!

        $E(K_{e}, m) = c$

        \begin{itemize}
            \item $E$ ist die Verschlüsselungsfunktion
            \item $K$ ist der Schlüssel. Man unterscheidet zwischen symmetrischer $K_{e} = K_{d}$ und asymmetrischer Verschlüsselung, bei der zwei Schlüssel gibt, für die meist $K_{e} = K^{+}$ und $K_{d} = K^{-}$ gilt.
            \item $m$ ist die Klartextnachricht.
            \item $c$ ist der verschlüsselte Text. Die Abkürzung steht für \textit{Cipher}.
        \end{itemize}
    
    \item Was ist ein XOR Cipher?

        Bei einem XOR Cipher wird die Klartextnachricht $m$ mithilfe eines Schlüssels $K$ mittels XOR-Operation verschlüsselt: $m \xor m = c$
    
    \item Was bedeutet Interception?

        Interception passiert, wenn Nachrichten abgefangen werden. Das kann physisch, durch Veränderung der Verkabelung, oder logisch, durch Rekonfiguration von DNS oder ARP erfolgen.
    
    \item Was bedeutet Eavesdropping?

        Eavesdropping ist das Abhören von Nachrichten. Das kann physisch, durch \textit{Wiretapping} oder Mitlesen des Netzwerkverkehrs, oder logisch durch die Umleitung des Verkehrs erfolgen.
    
    \item Warum nennt man es einen passiven Angriff?

        Eavesdropping ist passiv, da der Angreifer den Datenverkehr nicht manipuliert.
    
    \item Wie können Angreifer an die Daten herankommen?

        \begin{itemize}
            \item physisch: \textit{Wiretapping} oder Mitlesen des Netzwerkverkehrs.
            \item logisch: Umleitung des Verkehrs.
        \end{itemize}
    
    \item Wie kann Eavesdropping verhindert werden?

        Verschlüsselung der Nachrichten
    
    \item Was versteht man unter lawful interception?

        "Lawful Interception (LI) ist ein Sicherheitsverfahren, bei dem ein Diensteanbieter oder Netzbetreiber die abgefangene Kommunikation von Privatpersonen oder Organisationen sammelt und den Strafverfolgungsbehörden zur Verfügung stellt."
    
    \item Was ist eine Replay Attack?

        Eine Replay Attacke ist, wenn ein Angreifer eine Nachricht mitliest, kopiert und mehrmals an einen Empfänger sendet.
    
    \item Wie können Replay Attacks verhindert werden?

        Mithilfe von Sequenznummern. Wenn dieselbe Nachricht mit derselben Sequenznummer gesendet wird, handelt es sich um dieselbe Nachricht und sollte trotz mehrfacher Wiederholungen als eine Nachricht behandelt werden.
    
    \item Was ist eine Modification Attack?
    
    \item Geben Sie Beispiele an!
    
    \item Erläutern Sie Gegenmaßnahmen!
    
    \item Was ist eine Impersonation Attack? Wie kann sie aussehen?
    
    \item Was ist eine MitM attack?
    
    \item Wie kann sie verhindert werden?
    
    \item Was ist eine DoS attack?
    
    \item Was bedeutet DDos?
    
    \item Geben Sie ein Beispiel für eine DoS attack an!
    
    \item Was versteht man unter einer Amplified DDoS Attack?
    
    \item Beschreiben Sie wie eine NTP DDoS Attack funktioniert!
    
    \item Wie kann man dem on premise bzw. in der cloud begegnen?
    
    \item Welche zwei Ansätze gibt es, um Verschlüsselung zu brechen?
    
    \item Nennen sie zwei Arten von Angriffen, um Schlüssel herauszufinden!
    
    \item Was versteht man unter Kryptoanalyse?
    
    
    \item Welche drei unterschiedlichen Arten von Kryptoanalyse gibt es?
    
    \item Was sind side channel attacks?
    
    \item Wie funktioniert eine brute-force attack auf Passwörter bzw. auf Verschlüsselung?
    
    \item Wovon hängen die Erfolgschancen von brute-force attacks vorwiegend ab?
    
    \item Was ist eine dictionary attack?
    
    \item Wie funktioniert statistische Kryptoanalyse mit cyphertext-only? Was ist eine Voraussetzung dafür?
    
    \item Beschreiben Sie, wie eine Known-Plaintext Attack funktioniert?
    
    \item Warum ist eine Chosen-Plaintext Attack wirkungsvoller?
    
    \item Nennen Sie einen Satz mit 26 verschiedenen Buchstaben!
    
    \item Was nutzen Side Channel Attacks aus? Nennen Sie Beispiele für Side Channel Attacks!

\end{enumerate}

\section*{Kapitel 2}

\begin{enumerate}
    \item Nennen Sie eine allgemeine Notation für Verschlüsselung!

        $$c = E(K_e, m)$$
    
    \item Was sind symmetrische und asymmetrische Kryptografie?

        Bei der \textbf{symmetrischen Kryptografie} werden Texte mit einem symmetrischen Schlüssel verschlüsselt. Es kann sich dabei um den gleichen Schlüssel $K$ handeln, mit dem ein Text ver- und wieder entschlüsselt wird, oder, $K_d$ kann aus $K_e$ errechnet werden.
        Beispiele hierfür sind \textit{One-time Pads}, \textit{Stream Cipher}, \textit{Block Cipher}.
    
        Bei der \textbf{asymmetrischen Kryptografie} gibt es zwei Schlüssel $K_e$ und $K_d$, wobei sich $K_d$ nicht aus $K_e$ errechnen lässt. Meistens ist $K_e$ öffentlich, während der $K_d$ privat bleiben muss, damit die Nachricht nicht von jedem entschlüsselt werden kann. Ein Beispiel hierfür ist \textbf{RSA}.
    
    \item Was benötigt symmetrische Kryptografie, ehe sie angewendet werden kann?

        Für symmetrische Kryptografie muss der geteilte Schlüssel $K_s$ über einen sicheren Kanal ausgetauscht werden.
    
    \item Was sind one-time pads?

        One-time Pads sind Schlüssel, die unter idealen Bedingungen \textit{Perfect Privacy}  bieten und damit nicht knackbar sind. Mit ihnen werden Nachrichten mittels XOR-Operation verschlüsselt.
        Die Bedingungen für Perfect Privacy sind:
        
        \begin{itemize}
            \item zufälliger Schlüssel $K$
            \item $len(K) \geq len(m)$
            \item Schlüssel $K$ darf nur einmal genutzt werden
        \end{itemize}

    \item Was sind Stream Ciphers?

        Stream Cipher sind Key-Stream Generatoren, die einen Schlüssel $K$ bestimmter Länge um die Länger einer Nachricht $m$ expandieren. Mit diesem Key-Stream kann eine Nachricht bitweise mittels XOR Operation verschlüsselt werden.
        Stream Ciphers arbeiten mit Bits, während \textit{Block Ciphers} mit Blöcken arbeiten.
    
    \item Was sind Block Ciphers?

        Mit Block Ciphers werden Nachrichten in einzelne, gleich große Blöcke unterteilt. Die Nachrichtenblöcke werden dann blockweise auf verschlüsselte Blöcke abgebildet.
    
    \item Was ist ein Transposition Cipher?

        In einem Transposition Cipher werden nur die Positionen der einzelnen Buchstaben verändert. 
    
    \item Wie funktioniert ein Skytale? Was ist der Schlüssel?

        Ein Skytale ist ein Stab, der als Schlüssel fungiert, und um den ein Band, auf dem ein Text steht, gewickelt wird. Ohne den Stab sind die Buchstaben auf dem Band zusammengewürfelt. Erst durch das Wickeln um den Stab wird der Text erkenntlich gemacht.
    
    \item Was ist ein Substitution Cipher? Was ist der Schüssel?

        Bei einem Substitution Cipher wird ein Buchstabe mit einem anderen substituiert. Der Schlüssel ist dabei die eindeutige Abbildung, von einem Buchstaben auf einen anderen. Das heißt, ein Buchstabe kann nicht auf zwei Buchstaben abgebildet werden, wodurch die eben die Eindeutigkeit nicht mehr gegeben wäre. Der Substitution Cipher ist ein \textit{monoalphabetischer Cipher}.
    
    \item Was ist Caesar’s Cipher? Was ist der Schlüssel?

        Der Caesar’s Cipher ist ein spezieller Fall eines monoalphabetischen Ciphers, bei dem alle Buchstaben in einem Text um einen bestimmten Schlüssel $K \in [0, 25]$ verschoben werden.
        Wenn der Schlüssel $K = 13$, spricht man auch von Caesar-ROT\item
    
        \enquote{Network Security ist spannend} wird bei $K = 13$ zu \enquote{arGJBEx frpHEvGL vFG FCnAArAq}, wobei dann N auf A, E auf R usw. abgebildet werden.
    
    \item Was ist Polyalphabetic Substitution? Was ist der Schlüssel?

        Bei der polyalphabetischen Substitution werden mehrere Alphabete $n=3, M_1, M_3, M_7$ verwendet, um einen Text $m$ zu verschlüsseln. Dabei bestimmt die Position des zu substituierenden Buchstabens, welches Alphabet verwendet werden soll. Ein Doppelbuchstabe kann damit zu zwei verschiedenen Buchstaben substituiert werden, je nachdem, in welchem Alphabet sich dieser befindet. Da meist $len(m) \geq n$, rotieren die Alphabete in derselben Reihenfolge durch.
    
    \item Nennen Sie einen bekannten Polyalphabetic Cipher!

        Ein bekanntes Beispiel ist der \href{https://en.wikipedia.org/wiki/Vigenère_cipher}{Vigenère cipher}.
    
    \item Was ist der Unterschied zwischen einem RNG und einem echten PRNG?

        Der \textbf{R}andom \textbf{N}umber \textbf{G}enerator (RNG) generiert echte Zufallszahlen auf der Basis von physikalischen Prozessen, wie Rauschen. Er ist nicht-deterministisch und unvorhersehbar.

        Der \textbf{P}seudo \textbf{R}andom \textbf{N}umber \textbf{G}enerator (PRNG) generiert statistisch zufällige Zahlen auf Basis eines \textit{Seeds}. Bleibt der Seed gleich, wird immer dieselbe Folge von Zufallszahlen generiert. Dieser Generator ist nicht kryptografisch sicher, da sich die Folge beobachten und vorhersagen lässt.
    
    \item Was ist ein statistically secure PRNG?

        Ein statistisch sicherer PRNG unterscheidet sich vom PRNG insoweit, als, dass er zwar durch den Seed auch deterministisch, aber nicht vorhersehbar ist.
    
    \item Wie funktioniert ein Stream Cipher? Beschreiben Sie seine Arbeitsweise mit geeigneter Notation! Was ist der Schlüssel?

        Ein Stream Cipher ist ein PRNG, bei dem der Seed als Schlüssel fungiert und bei dem eine Nachricht $m$ bitweise per XOR-Operation mit dem Keystream $ks$ verschlüsselt wird.

        \begin{itemize}
            \item Verschlüsselung: $c(i) = ks(i) \xor m(i)$.
            \item Entschlüsselung: $m(i) = ks(i) \xor c(i)$
        \end{itemize}

        Der Schlüssel ist symmetrisch.
    
    \item Nennen Sie Vorteile von Stream Ciphers!

        \begin{enumerate}
            \item Verschlüsselung von einem Bit auf einmal. Das heißt, der Sender kann direkt verschlüsseln, ohne auf ganze Blöcke zu warten, wie es beim Block Cipher der Fall ist. Stream Cipher eignen sich damit für Realzeitanwendungen.
            \item Singlebit-Fehler im Ciphertext $c$ führen zu Singlebit-Fehlern im Klartext $m$ und können mithilfe der \textit{Forward Error Correction (FEC)} korrigiert werden.
        \end{enumerate}
    
    \item Wofür steht RC4?

        \enquote{Ron's Cipher 4} ist ein (Byte-orientierter) Stream Cipher.
    
    \item Was ist ein Vorteil von RC4?

        \begin{enumerate}
            \item variable Schlüssellänge,
            \item performant,
            \item einfacher Algorithmus, der sich damit auch einfach implementieren lässt. Das führt wiederum zur Minimierung von Fehlern bei der Implementierung und der Verminderung von \textit{Side-Channel Attacken}.
        \end{enumerate}
    
    \item Was ist \textit{Key Scheduling} in RC4? Wie funktioniert es in Grundzügen?

        Key Scheduling dient dazu eine Substitutionstabelle

    \item Wie funktioniert die RC4 Verschlüsselung in Grundzügen? Wie viele zufällige Bits werden dabei auf einmal erzeugt? Auf welcher internen Datenstruktur arbeitet RC4? Wie wird diese im Laufe 
    der Verschlüsselung verändert?

        RC4 besteht aus zwei Schritten:

        \begin{enumerate}
            \item Key Scheduling: Zustand initialisieren
            \item Verschlüsselung: Keystream generieren und den Klartext-Stream mit dem Keystream per XOR-Operation verschlüsseln
        \end{enumerate}

        Es werden $m$-viele Bits erzeugt, wobei $m$ die Länge der Nachricht, die verschlüsselt werden soll, ist. RC4 baut auf einer Substitutions-Box, kurz \textit{S-Box}. Diese Struktur wird so verändert, dass Buchstaben mit den Indexen $i = (i + 1) (mod 256)$ und $j = (j + S[i]) (mod 256)$ miteinander vertauscht werden.
    
    \item Erläutern Sie T[] und S[], wofür sie verwendet werden, und wie der Schlüssel verwendet wird!

        $S$[] ist die S-Box mit einer Länge von 255 Bytes. $T$[] ist ein temporäres Array, das verwendet wird, um die S-Box zu befüllen. Am Anfang ist die S-Box nur mit den Werten von 0 bis 255 befüllt. In $T$ wird der Schlüssel $K$ mehrere Male hintereinander gereiht, da der Schlüssel $K$ kleiner als die maximale Länge von $255 B = 2048 Bits$ sein kann. Die S-Box wird dann mithilfe von T, das potenziell mehrere Kopien des Schlüssels enthält, permutiert.
    
    \item Wofür wird RC4 verwendet?

        \begin{itemize}
            \item WiFi: WEP, WPA, WPA2
            \item Microsoft Point-to-Point Encryption Protocol
            \item Remote Desktop Protocol
        \end{itemize}
    
    \item Ist die Verwendung von RC4 empfehlenswert?

        Nein, da RC4 heutzutage als unsicher betrachtet wird. Anfangs wurde RC4 geheim gehalten, um Sicherheit durch die Geheimhaltung des Algorithmus zu garantieren. 
    
    \item Wie funktioniert Salsa20 in Grundzügen? Wie viele zufällige Bits werden dabei auf einmal erzeugt? 
    Auf welcher internen Datenstruktur arbeitet Salsa20? Wie wird diese im Laufe der 
    Verschlüsselung verändert?

        
    
    \item Was ist ChaCha? Wie unterscheidet es sich von Salsa20? Was ist der Vorteil?

        
    
    \item Wo wird ChaCha verwendet?
    
    \item Welche Stream Ciphers kennen Sie noch? Welche davon sind noch empfehlenswert?
    
    \item Wie funktioniert ein Block Cipher prinzipiell?
    
    \item Was ist das Problem bei einer naiven Implementierung und wie wird das Problem ge- 
    löst?
    
    \item Was ist ein Feistel Cipher? Wie funktioniert er? Welche Methoden basieren auf Feistel 
    Ciphers?
    
    \item Was heißt DES? Was heißt NIST? Was heißt FIPS?
    
    \item Wie groß ist die Block Size bei DES, wie groß der Schlüssel? Was sind round keys?
    
    \item Warum benötigt DES einen Key Schedule? Was macht er?
    
    \item Was ist eine S-box? Was ist eine P-box?
    
    \item Wie funktioniert die Entschlüsselung mit DES?
    
    \item Was sind Schwächen von DES?
    
    \item Was ist Triple-DES (3DES)? Was ist seine key size?
    
    \item Warum wird nicht 2DES verwendet?
    
    \item Wird 3DES verwendet? Welches Problem von DES wird durch 3DES nicht gelöst?
    
    \item Was ist ein weiterer Nachteil von 3DES gegenüber neueren Ciphers?
    \item Was bedeutet AES? Welche Block Size hat er? Welche Key Sizes unterstützt er?


    \item Wie steht es mit der Performance von AES?
    
    \item Wie funktioniert AES strukturell?
    
    \item Wie geht der Schlüssel ein?
    
    \item Warum benötigt man einen Key Scheduling Algorithm?
    
    \item Warum werden Operation Modes für Block Ciphers verwendet?
    
    \item Was heißt ECB und wie funktioniert es? Was sind seine Probleme?
    
    \item Was heißt CBC und wie funktioniert es? Was sind seine Probleme?
    
    \item Was heißt CTR und wie funktioniert es? Was sind seine Probleme?
    
    \item Was bedeutet synchronous im Kontext von ciphers? Geben Sie zwei Beispiele an!
    
    \item Was sind self-synchronization block ciphers?
    
    \item Was heißt OFB und wie funktioniert es? Was sind seine Probleme?
    
    \item Was heißt CFB und wie funktioniert es? Was sind seine Probleme?
    
    \item Was ist eine Hash Funktion?
    
    \item Geben Sie einfache Hashes an und diskutieren Sie deren Probleme im Kontext Krypto- 
    graphie!
    
    \item Was ist für kryptografische Hashes essenziell?
    
    \item Welche Arten von \textit{Resistance} kennen sie und was bedeuten sie?
    
    \item Nennen Sie Synonyme für kryptografische Hashes!
    
    \item Warum ist die Internet Checksumme kein guter Message Digest?
    
    \item Was ist Ziel und Funktionsweise der Merkle-Damgard-Construction?
    
    \item Warum benötigt man dafür einen IV? Warum benötigt man padding?
    
    \item Was heißt MD5? Nach welchem Prinzip funktioniert MD5? Was ist seine Blockgröße? Wie groß ist seine Digest Sizes?
    
    \item Ist MD5 noch sicher? Wofür kann er verwendet werden?
    
    \item Was heißt SHA?

        SHA steht für \textbf{S}ecure \textbf{H}ash \textbf{A}lgorithm.
    
    \item Nach welchem Prinzip funktioniert SHA-1? Was ist seine Blockgröße? Was ist seine 
    Digest Size? Welche Attacke gibt es gegen SHA-1?

        SHA-1 ist eine Merkle-Damgard Konstruktion. Es gibt eine Blockgröße von 512 Bit und hat einen \textit{Message Digest} von 160 Bit. Der Message Digest ist ein Hash-Output.

        Gegen SHA-1 gibt es die \textbf{Collision-Attack}. Das bedeutet, dass zwei verschiedene Inputs zum selben Output führen.


    \item Was ist ein wesentlicher Unterschied zwischen SHA-1 und SHA-2? Welche Varianten gibt 
    es?

        SHA-2 produziert im Vergleich zu SHA-1 längere Digests.
    
    \item Was ist SHA-3?
    
    \item Was sind Message Authentication Codes? Was sind Synonyme?
    
    \item Was ist das Problem bei Simpled Keyed Hashes?
    
    \item Was ist HMAC und wie funktioniert es?

        HMAC steht für Keyed-\textbf{H}ashing \textbf{M}essage \textbf{A}thentication \textbf{C}ode und ist eine standardisierte Einweg-Hashfunktionen, die mit einem Schlüssel $k$ arbeitet, aber Hashes anstelle von Verschlüsselung verwendet.

        $t = H(k \xor opad |H(k \xor ipad|m))$
    
    \item Was können Sie über seine Sicherheit aussagen?
    
    \item Was ist CBC-MAC? Was ist ein Problem und eine Gegenmaßnahme?
    
    \item Was ist Poly1305? Wie funktioniert es strukturell? Woher kommt sein Name?
    
    \item Was bedeutet (Non-)Malleability? Geben Sie Beispiele an!
    
    \item Was ist authenticated encryption? Was sind Ziele?
    
    \item Was heißt AEAD und was ist damit gemeint? Wie funktioniert AEAD?
    
    \item Was bedeuten MAC-and-encrypt, MAC-then-encrypt, Encrypt-then-MAC?
    
    \item Diskutieren Sie die Sicherheit dieser Varianten!
    
    \item Was heißt CCM? Was sind Vorteile? Wie funktioniert es? Wie funktioniert die AEAD 
    version? Wo wird CCM angewendet?
    
    \item Was heißt GCM? Wie funktioniert es? Was sind seine Vorteile?
    
    \item Was ist GMAC?
    
    \item Was ist ChaCha20-Poly1305? Wie funktioniert es strukturell?
    
    \item Was ist ein grundlegender Unterschied zwischen symmetrischer und asymmetrischer 
    Kryptografie?
    
    \item Wie funktioniert Public Key Kryptografie?
    
    \item Warum kann bei symmetrischer Kryptografie der Key, der zur Verschlüsselung genutzt wird, nicht veröffentlicht werden?
    
    \item Was ist der kleinste gemeinsame Teiler von 169 und 221?
    
    \item Was ist $\phi(50)$?
    
    \item Was ist $\phi(5917)$? Hinweis: Die Primfaktoren von 5917 lauten 61 und     \item

    \item Auf welchen Problemen der Zahlentheorie basiert die meiste asymmetrische Kryptografie?
    
    \item Warum ist es im Kontext von RSA wichtig, dass d und e inverse zueinander sind?
    
    \item Warum ist es schwer $\phi(n)$ zu berechnen, wenn nur n und e bekannt sind?
    
    \item Was passiert beim vorgestellten Textbook RSA, wenn zweimal dieselbe Nachricht 
    verschlüsselt wird? Wie kann dieses Problem behoben werden?
    
    \item Wie viele Multiplikationen sind notwendig, um 139118 zu berechnen, wenn der naive 
    Algorithmus aus der Schule verwendet wird?
    
    \item Wie viele Multiplikationen sind notwendig mit dem Square-and-Multiply Algorithmus?
    
    \item Leiten Sie aus den Eigenschaften einer Gruppe her, dass das neutrale Element in einer 
    Gruppe eindeutig ist!
    
    \item Was ist ein Shared Secret? Wie bekommen beide Kommunikationspartner das shared secret?
    
    \item Was ist non-repudiation?
    
    \item Vergleiche RSA Signaturen mit dem normalen RSA Algorithmus!
    
    \item Warum darf $k$ im Kontext von DSA nie mehrfach verwendet werden?

    \item Wie funktioniert ElGamal?

        ElGamal wird mithilfe eines Beispiels erklärt, bei dem Alice eine Nachricht verschlüsselt an Bob senden möchte.
    
        Bei \textbf{ElGamal} wählt Alice ein zufälliges $y \in \{1, 2, ..., q - 1\}$, das nur einmal verwendet werden sollte, und berechnet mit $y$ und mit Bobs öffentlichem Schlüssel $h_{Bob}$ ein Shared Secret $s = h_{Bob}^y = (g^{x_{Bob}})^{y} = g^{xy}$. $h_{Bob} = g^{x_{Bob}}$ ist Bobs öffentlicher Schlüssel und $x_{Bob}$ ist Bobs privater Schlüssel. Bei $g$ handelt es sich um einen Generator der Gruppe $G$.
        Mit $s$ kann Alice die Nachricht $m$ verschlüsseln, sodass sie $c_2 = m * s$ erhält. Zusätzlich zur Nachricht gibt sie $c_1 = g^{y}$ mit.
        Bob kann $m$ aus $m = (c_1)^{-x} * c_2 = ((g^{y})^{-x}) * (g^{xy} * m) = g^{-xy+xy} * m = g^{0} * m$ berechnen. Bob kennt $x$, da es sich um seinen privaten Schlüssel handelt.

        Beide Parteien können das Shared Secret $s$ ausrechnen. Alice rechnet $s = (g^{x_{Bob}})^{y} = g^{xy}$ aus und Bob rechnet $s = (g^{y})^{x_{Bob}} = g^{xy}$ aus.

    \item Wozu wird der Diffie-Hellman Schlüsseltausch verwendet?

        
    
    \item Was hat Diffie-Hellman mit ElGamal zu tun?

        Diffie-Hellmann und ElGamal beruhen beide auf dem Prinzip des \textit{Shared Secrets}, das sich beide Parteien jeweils berechnen, und auf Operationen, die in einer Gruppe $G$ ausgeführt werden.
    
    \item Was weiß ein Angreifer, der die gesamte Kommunikation eines Diffie-Hellmann Schlüsselaustausch mitgehört hat? Kann er damit das Shared Secret berechnen?
    
    \item Definieren Sie Forward-secrecy! (Notwendig!)

        Forward secrecy 
    
    \item Angenommen ein Angreifer hört die Kommunikation eines DH Schlüsseltauschs ab. Zu 
    einem späteren Zeitpunkt nach dem Austausch findet der Angreifer die Private Keys für die 
    verwendeten Signaturen heraus. Warum nützt ihm dies nichts?
    
    \item Machen Sie sich über die Folien hinaus mit elliptischen Kurven über R vertraut: 
    https://andrea.corbellini.name/ecc/interactive/reals-add.html.
    
    \item Machen Sie sich auch mit elliptischen Kurven über einem endlichen Körper \href{https://andrea.corbellini.name/ecc/interactive/modk-add.html}{vertraut}: 
    
    \item Wie lautet die \enquote{Regel}, mit der aus klassischen Verfahren ein Verfahren mit 
    elliptischen Kurven konstruiert werden kann?


    \item Was sind die Vorteile von elliptischen Kurven gegenüber klassischer asymmetrischer Kryptografie?
    
    \item Welche Vorteile bietet Curve25519?
    
    Zusatz: Informieren Sie sich über \href{https://en.wikipedia.org/wiki/Dual_EC_DRBG}{Wikipedia} über ein Verfahren mit elliptischen Kurven, dass diese Vorteile nicht bietet!

    \item Welche Vorteile bieten symmetrische und asymmetrische Kryptografie?
    
    \item Wie können die Vorteile von symmetrischer und asymmetrischer Kryptografie kombiniert 
    werden?
    
    \item Vergleichen Sie die Sicherheit von RSA und ECC bei einer festen vorgegebenen Schlüssellänge!
    
    \item Was können Quantencomputer effizient tun, was klassische Computer nicht können?
    
    \item Ist symmetrische Kryptografie anfällig für Angriffe durch Quantencomputer?

\end{enumerate}
\end{document}

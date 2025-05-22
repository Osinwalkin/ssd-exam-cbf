# Secure Desktop Vault - Eksamensprojekt

Dette projekt er en desktop-applikation udviklet i Python med CustomTkinter GUI til sikker opbevaring og håndtering af følsomme data (såsom API-nøgler, konfigurationsparametre og adgangskoder) for en enkelt bruger lokalt på brugerens computer.

## Formål

Formålet med projektet er at demonstrere design og implementering af en sikker applikation, der fokuserer på relevante trusler mod lokal dataopbevaring og applikationsadgang, og som følger "Secure by Design"-principper samt udvalgte OWASP Proactive Controls.

## Kernefunktioner og Sikkerhedsmekanismer

*   **Master Password Adgangskontrol:** Adgang til vaulten og secrets er beskyttet af en master password som brugeren indtaster på første run.
*   **Password Hashing:** Brugerens master password hashes med **Argon2id**, en Key Derivation Function (KDF), før den sammenlignes eller gemmes (kun hashen gemmes). Dette beskytter mod offline brute-force angreb (hvis nogen skulle få adgang til pcen).
*   **Salt:** Der anvendes tilfældigt genererede salts både til password hashing (håndteres internt af Argon2id-library) og til deriving af krypteringsnøglen (via HKDF).
*   **Derivation af krypteringsnøgle:** En dedikeret krypteringsnøgle derives fra master passwordet og et separat salt ved hjælp af HKDF med SHA256. Dette sikrer at master passwordet ikke direkte bruges som krypteringsnøgle.
*   **Autentificeret Kryptering (AEAD):** Følsomme data (gemte secrets) krypteres med **AES-256** via `cryptography.fernet` libary. AES-GCM tilbyder både fortrolighed (confidentiality) og integritet/autenticitet (integrity/authenticity), hvilket beskytter mod både datalækager og datamanipulation (tampering).
*   **Sikker Opbevaring:**
    *   Master password hashen og saltet til nøglederivation gemmes lokalt.
    *   De krypterede secrets gemmes i en separat fil (`secrets.dat`).
    *   Det skal siges at man kan se alle disse filer i github projektet da det er til en eksamen og vi skal kunne se resultaterne.
*   **Brugergrænseflade:** simpel GUI bygget med CustomTkinter library.
    *   Dialog vindue til opsætning/indtastning af master password.
    *   Dialog vindue til tilføjelse af nye secrets (label og værdi).
    *   Visning af gemte secrets (labels vises, værdier er obfuskeret indtil kopiering).
    *   Funktionalitet til at kopiere secret-værdier til udklipsholderen.

## Teknologier

*   **Python 3.10**
*   **CustomTkinter:** GUI
*   **cryptography:** Til Fernet (AES-GCM kryptering) og HKDF.
*   **argon2-cffi:** Til Argon2id password hashing.

## Setup og Installation

2.  **Klon Repository (hvis relevant):**

    git clone repository-url
    cd repository-navn

3.  **Opret og lav virtual environment:**
    python -m venv venv

    venv\Scripts\activate

4.  **Installer Afhængigheder:**
    pip install -r requirements.txt

## Kørsel af Applikationen
Fra projektets root venv aktiveret:
python -m secure_vault.app
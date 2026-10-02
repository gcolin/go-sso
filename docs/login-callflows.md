# Callflows de login (datanode-sso)

Flux HTML et OAuth du serveur SSO Go. Les chemins sont relatifs à `server.publicBaseUrl`
(ex. `https://oauth2.tregorechecs.fr` → pas de préfixe ; `http://localhost:8080/sso` → préfixe `/sso`).

Les flèches `S->>J` marquent une réécriture **en place** de `sso-server.json` (`loader.Save`).

## Légende cookies JWT


| Cookie                                      | Type JWT               | Rôle                                                                                 |
| ------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------ |
| `datanode_sso_session`                      | `sso_session`          | Session authentifiée                                                                 |
| `datanode_sso_session_pending_registration` | `pending_registration` | Login temporaire après inscription / renvoi mail (TTL = `emailVerificationTtlHours`) |
| `datanode_sso_session_pending_2fa`          | `pending_2fa`          | 2FA en cours (API)                                                                   |




## Écritures JSON (`loader.Save`)


| Opération                             | Quand                          | Champs typiques                                                  |
| ------------------------------------- | ------------------------------ | ---------------------------------------------------------------- |
| `Create`                              | `POST /register`               | `users[]` + nouvel user (`emailVerified: false` si mail enabled) |
| `MarkEmailVerified`                   | `GET /verify-email`            | `users[].emailVerified = true`                                   |
| `ResolveExternalLogin` (lier)         | callback IdP, email déjà connu | `authProvider`, `externalSubject`, `emailVerified: true`         |
| `ResolveExternalLogin` (provisionner) | callback IdP + `autoProvision` | nouveau user fédéré (`emailVerified: true`)                      |


---



## 1. Connexion locale (compte validé)

```mermaid
sequenceDiagram
  actor U as Utilisateur
  participant B as Navigateur
  participant S as SSO

  U->>B: Ouvre / ou /login?returnUrl=…
  B->>S: GET /login
  S-->>B: Page login (IdP + formulaire)
  U->>B: email + mot de passe
  B->>S: POST /login (returnUrl)
  S->>S: AuthenticateStatus OK
  S->>S: WriteSession (cookie sso_session)
  S-->>B: 302 → returnUrl
  B->>S: GET returnUrl (session)
```



---



## 2. Connexion locale (email non validé)

```mermaid
sequenceDiagram
  actor U as Utilisateur
  participant B as Navigateur
  participant S as SSO
  participant M as SMTP

  U->>B: POST /login
  B->>S: POST /login
  S->>S: AuthEmailNotVerified
  S-->>B: 302 /login/unverified?email=&returnUrl=
  B->>S: GET /login/unverified
  S-->>B: Message + bouton renvoi + lien se connecter

  alt Renvoyer l'email
    U->>B: Renvoyer l'email de validation
    B->>S: POST /verify-email/resend (pending=1)
    S->>M: sendVerificationEmail
    S->>S: cookie pending_registration
    S-->>B: 302 /register/pending?email=&returnUrl=
  else Déjà un compte
    U->>B: Lien se connecter
    B->>S: GET /?returnUrl=
  end
```



---



## 3. Inscription + validation email + auto-login

```mermaid
sequenceDiagram
  actor U as Utilisateur
  participant B as Navigateur
  participant S as SSO
  participant J as sso-server.json
  participant M as SMTP

  U->>B: GET /register?returnUrl=
  B->>S: GET /register
  S-->>B: Formulaire inscription
  U->>B: email, nom, mot de passe
  B->>S: POST /register
  S->>S: Create user (emailVerified=false si mail.enabled)
  S->>J: Save users[] (nouvel utilisateur)
  S->>M: email avec JWT type=email_verification
  S->>S: cookie pending_registration
  S-->>B: 302 /register/pending?email=&returnUrl=

  Note over U,M: U clique le lien du mail
  U->>B: GET /verify-email?token=JWT
  B->>S: GET /verify-email
  S->>S: Parse JWT
  S->>S: MarkEmailVerified
  S->>J: Save users[].emailVerified=true
  S-->>B: Page succès validation

  U->>B: J'ai validé mon compte
  B->>S: POST /register/pending
  S->>S: emailVerified ?
  alt Non validé
    S-->>B: Même page + erreur
  else Validé + cookie pending_registration OK
    S->>S: Clear pending cookie
    S->>S: WriteSession
    S-->>B: 302 → returnUrl
  else Validé sans cookie
    S-->>B: 302 /?messageKey=flash.register.success&returnUrl=
  end
```





### Lien mail

```
{publicBaseUrl}/verify-email?token={JWT}
```

Claims JWT `email_verification` : `sub` (userId), `email`, `type`, `exp` (TTL heures).

---



## 4. OAuth authorize → login → consent → code

```mermaid
sequenceDiagram
  actor U as Utilisateur
  participant App as Client OAuth
  participant B as Navigateur
  participant S as SSO

  App->>B: Redirect authorize
  B->>S: GET /oauth/authorize?response_type=code&client_id&redirect_uri&…&code_challenge
  alt Pas de session
    S-->>B: Page login (returnUrl = URL authorize courante)
    U->>B: POST /login
    B->>S: POST /login
    S->>S: Session cookie
    S-->>B: 302 → returnUrl (= /oauth/authorize?…)
    B->>S: GET /oauth/authorize (avec session)
  end
  alt Consentement requis
    S-->>B: Page consent
    U->>B: Autoriser
    B->>S: POST /oauth/authorize/decision
  end
  S-->>B: 302 redirect_uri?code=&state=
  B->>App: Callback avec code
  App->>S: POST /oauth/token (code + code_verifier)
  S-->>App: access_token (+ id_token si openid)
```



---



## 5. Fédération IdP externe (Google / Microsoft / …)

```mermaid
sequenceDiagram
  actor U as Utilisateur
  participant B as Navigateur
  participant S as SSO
  participant J as sso-server.json
  participant IdP as IdP externe

  U->>B: Clic « Se connecter avec X »
  B->>S: GET /auth/external/{providerId}?returnUrl=
  S->>S: state + PKCE
  S-->>B: 302 IdP authorize
  B->>IdP: Login IdP
  IdP-->>B: 302 callback SSO
  B->>S: GET /auth/callback/{providerId}?code=&state=
  Note over S: Aussi /realms/{realm}/broker/{providerId}/endpoint
  S->>IdP: Token exchange + userinfo
  S->>S: ResolveExternalLogin

  alt User local trouvé par email → lier
    S->>J: Save authProvider + externalSubject + emailVerified=true
  else Auto-provision (federation.autoProvision)
    S->>J: Save users[] (nouvel user fédéré, emailVerified=true)
  else Déjà lié
    S->>S: Reprend le user existant
  else Auto-provision désactivé
    S-->>B: Erreur external user not allowed
  end

  S->>S: WriteSession
  S-->>B: 302 → returnUrl
```



---



## 6. Login JSON API

```mermaid
sequenceDiagram
  participant C as Client
  participant S as SSO

  C->>S: POST /api/auth/login {email,password}
  alt OK sans 2FA
    S-->>C: 200 + Set-Cookie session
  else Email non vérifié
    S-->>C: 403 email_not_verified
  else 2FA requis
    S-->>C: pending 2FA (cookie pending_2fa)
    C->>S: POST /api/auth/2fa/verify {code}
    S-->>C: 200 + session
  else Identifiants invalides
    S-->>C: 401
  end
```



---



## Pages HTML liées


| Route                     | Rôle              | Écriture JSON        |
| ------------------------- | ----------------- | -------------------- |
| `POST /register`          | Inscription       | `Create` → `users[]` |
| `GET /verify-email`       | Activation mail   | `MarkEmailVerified`  |
| `GET /auth/callback/{id}` | Retour fédération | liaison ou provision |


---



## Config utile

```json
{
  "security": {
    "publicRegistrationEnabled": true,
    "emailVerificationTtlHours": 48,
    "sessionCookieSecure": true
  },
  "mail": {
    "enabled": true,
    "smtpHost": "…",
    "smtpPort": 587,
    "fromAddress": "…",
    "startTls": true
  }
}
```

Si `mail.enabled` est `false`, les comptes créés sont utilisables immédiatement (pas de `emailVerified=false`).
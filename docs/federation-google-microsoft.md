# Fédération Google, Microsoft, Facebook & Yahoo

Guide pour enregistrer un IdP OAuth/OIDC externe dans datanode-sso
(**Configuration → Fédération** dans l’admin, ou `federation.identityProviders` dans `sso-server.json`).

Consoles :

- **Microsoft Entra** : [https://entra.microsoft.com](https://entra.microsoft.com)
- **Google Cloud** : [https://console.cloud.google.com/](https://console.cloud.google.com/)
- **Meta for Developers** : [https://developers.facebook.com/](https://developers.facebook.com/)
- **Yahoo Developer Network** : [https://developer.yahoo.com/](https://developer.yahoo.com/)

## Redirect URI côté SSO

Par défaut, le callback est :

```text
{publicBaseUrl}/auth/callback/{providerId}
```

Exemple prod :

```text
https://oauth2.tregorechecs.fr/auth/callback/google
https://oauth2.tregorechecs.fr/auth/callback/microsoft
https://oauth2.tregorechecs.fr/auth/callback/facebook
https://oauth2.tregorechecs.fr/auth/callback/yahoo
```

- `{providerId}` = champ **ID** du fournisseur dans le SSO (`google`, `microsoft`, `facebook`, `yahoo`, …).
- L’URI déclarée chez l’IdP doit **matcher exactement** (schéma, host, chemin, pas de slash final en trop).
- Champ optionnel SSO **Redirect URI** : override uniquement si besoin (sinon laisser vide).

Le SSO utilise le flux **authorization code + PKCE S256** et exige un **email** + un **subject** (`sub` par défaut ; Facebook → `id`).

---

## Google

Console : [Google Cloud Platform](https://console.cloud.google.com/).

1. Choisir (ou créer) un projet.
2. Configurer l’écran de consentement OAuth (**APIs & Services → OAuth consent screen** / Google Auth Platform → Branding).
3. Créer un client OAuth :
   - **APIs & Services → Credentials → Create credentials → OAuth client ID**
   - Type : **Web application**
   - **Authorized redirect URIs** :  
     `https://oauth2.tregorechecs.fr/auth/callback/google`  
     (adapter host / id)
4. Noter **Client ID** et **Client secret**.

### Valeurs à saisir dans le SSO

| Champ SSO | Valeur |
|-----------|--------|
| ID | `google` |
| Display name | `Google` |
| Logo | `bi-google` *(ou vide si id=`google`)* |
| Enabled | oui |
| Client ID / secret | ceux de la console |
| Authorization URL | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token URL | `https://oauth2.googleapis.com/token` |
| UserInfo URL | `https://openidconnect.googleapis.com/v1/userinfo` |
| Scopes | `openid email profile` |
| Email claim | `email` |
| Name claim | `name` |
| Subject claim | `sub` |
| Redirect URI | *(vide)* sauf override |

Réf. Google OpenID Connect : [developers.google.com/identity/openid-connect](https://developers.google.com/identity/openid-connect/openid-connect).

---

## Microsoft (Entra ID)

Console : [Microsoft Entra admin center](https://entra.microsoft.com).

1. **Identity → Applications → App registrations → New registration**.
2. Nom de l’app ; comptes supportés selon le besoin (orga seule / multi-tenant / perso).
3. **Authentication → Add a platform → Web** :
   - Redirect URI :  
     `https://oauth2.tregorechecs.fr/auth/callback/microsoft`
4. **Certificates & secrets → New client secret** → noter la valeur (affichée une fois).
5. Sur la page Overview : noter **Application (client) ID**.
6. **Endpoints** : utiliser les URLs **v2.0** (remplacer `{tenant}` par l’ID du tenant, ou `common` / `organizations` / `consumers` selon l’audience).

### Valeurs à saisir dans le SSO

| Champ SSO | Valeur |
|-----------|--------|
| ID | `microsoft` |
| Display name | `Microsoft` |
| Enabled | oui |
| Client ID | Application (client) ID |
| Client secret | secret créé à l’étape 4 |
| Authorization URL | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` |
| Token URL | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| UserInfo URL | `https://graph.microsoft.com/oidc/userinfo` |
| Scopes | `openid email profile offline_access` |
| Email claim | `email` (sinon `preferred_username` si l’email n’est pas renvoyé) |
| Name claim | `name` |
| Subject claim | `sub` |
| Redirect URI | *(vide)* sauf override |

Réf. Microsoft identity platform (OIDC) : [learn.microsoft.com — OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).

> **Email Microsoft** : selon le type de compte, le claim `email` peut manquer. Si le login SSO échoue avec « pas d’email », passer le claim à `preferred_username` ou demander le scope qui expose l’email dans le token / UserInfo.

---

## Facebook (Meta)

Console : [Meta for Developers](https://developers.facebook.com/).

1. **My Apps → Create App** (type permettant **Facebook Login** / authentification).
2. Ajouter le produit **Facebook Login** → **Settings**.
3. **Valid OAuth Redirect URIs** :  
   `https://oauth2.tregorechecs.fr/auth/callback/facebook`
4. Sur **Settings → Basic** : noter **App ID** (client ID) et **App Secret**.
5. Demander la permission **email** (et `public_profile`) ; en mode Live, validation Meta peut être requise selon le statut de l’app.

### Valeurs à saisir dans le SSO

| Champ SSO | Valeur |
|-----------|--------|
| ID | `facebook` |
| Display name | `Facebook` |
| Enabled | oui |
| Client ID | App ID |
| Client secret | App Secret |
| Authorization URL | `https://www.facebook.com/v21.0/dialog/oauth` |
| Token URL | `https://graph.facebook.com/v21.0/oauth/access_token` |
| UserInfo URL | `https://graph.facebook.com/me?fields=id,name,email` |
| Scopes | `email,public_profile` |
| Email claim | `email` |
| Name claim | `name` |
| Subject claim | `id` |
| Redirect URI | *(vide)* sauf override |

> **Important Facebook**
> - Le profil Graph n’expose **pas** `sub` : mettre le subject claim à **`id`**.
> - Sans `?fields=id,name,email` sur UserInfo, l’**email** n’est souvent pas renvoyé (même avec le scope `email`).
> - Adapter `v21.0` à une version Graph supportée si besoin ([manual login flow](https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow)).

---

## Yahoo

Console : [Yahoo Developer Network](https://developer.yahoo.com/) — [Sign In With Yahoo](https://developer.yahoo.com/sign-in-with-yahoo/).

1. Se connecter au [Yahoo Developer Network](https://developer.yahoo.com/) et créer / ouvrir une application.
2. Activer **OpenID Connect** / **Sign In With Yahoo**.
3. Déclarer le **Redirect URI / Callback Domain** :  
   `https://oauth2.tregorechecs.fr/auth/callback/yahoo`
4. Noter **Client ID** (Consumer Key) et **Client Secret** (Consumer Secret).

### Valeurs à saisir dans le SSO

| Champ SSO | Valeur |
|-----------|--------|
| ID | `yahoo` |
| Display name | `Yahoo` |
| Enabled | oui |
| Client ID / secret | Consumer Key / Consumer Secret |
| Authorization URL | `https://api.login.yahoo.com/oauth2/request_auth` |
| Token URL | `https://api.login.yahoo.com/oauth2/get_token` |
| UserInfo URL | `https://api.login.yahoo.com/openid/v1/userinfo` |
| Scopes | `openid email profile` |
| Email claim | `email` |
| Name claim | `name` |
| Subject claim | `sub` |
| Redirect URI | *(vide)* sauf override |

Réf. Yahoo OpenID Connect : [developer.yahoo.com/oauth2/guide/openid_connect](https://developer.yahoo.com/oauth2/guide/openid_connect/).

---

## Après configuration

1. Enregistrer le fournisseur dans **Configuration → Fédération** (ou éditer un existant).
2. Vérifier `server.publicBaseUrl` (prod HTTPS, cookie Secure si besoin).
3. Page login : bouton IdP → `/auth/external/{id}` → retour `/auth/callback/{id}`.
4. Comptes : liaison par `(authProvider, externalSubject)` ; si email déjà connu en local, le SSO peut **lier** le compte ; sinon **provision** si `federation.autoProvision` est activé.

## Dépannage rapide

| Symptôme | Piste |
|----------|--------|
| `redirect_uri_mismatch` | URI console ≠ callback SSO (id / host / https) |
| Échec échange token | Client secret, token URL, PKCE |
| « pas d’email » | Scopes + claim ; Facebook → `fields=…,email` ; Microsoft → `preferred_username` |
| « pas d’identifiant » | Facebook → subject claim `id` (pas `sub`) |
| Bouton absent | Fournisseur **Enabled** + présent dans la config live |

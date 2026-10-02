# Docker list with IPs
_Exported on 10/2/2026 at 21:14:21 GMT+2 from Cursor (3.17.21)_

---

**User**

donne moi la liste des dockers avec l'ip et un nom dans pi@192.168.1.5

---

**Cursor**

Je vais récupérer sur le Pi la liste des conteneurs Docker avec nom et IP.

PowerShell a interprété la commande en local — je relance en SSH proprement quoté.

Je simplifie la commande pour éviter les problèmes de quoting PowerShell.

Quelques conteneurs affichent « invalid IP » — je vérifie s'ils sont en mode host.

Voici la liste des conteneurs Docker sur `pi@192.168.1.5` :

| Nom | IP | Statut |
|---|---|---|
| tomcat-app2 | 172.18.0.2 | Up 5 days |
| tomcat-test | 172.19.0.2 | Up 5 days |
| datanode-sso | 192.168.32.2 | Up 5 days |
| paheko | 172.21.0.2 | Up 18 hours (healthy) |
| tomcat-shared | 192.168.16.2 | Up 2 weeks |
| homeassistant | host network (IP du Pi) | Up 4 days |
| matterbridge | host network (IP du Pi) | Up 2 weeks |
| zigbee2mqtt | 172.31.0.3 | Up 2 weeks |
| mosquitto | 172.31.0.2 | Up 2 weeks |
| blog-wordpress-1 | 172.30.0.3 | Up 4 weeks |
| blog-db-1 | 172.30.0.2 | Up 4 weeks (healthy) |
| wordpress | 172.24.0.4 | Up 4 weeks |
| wordpress-nginx-1 | 172.24.0.2 | Up 4 weeks |
| wordpress_db | 172.24.0.3 | Up 4 weeks |
| keycloak | 172.23.0.2 | Up 4 weeks |
| postgres | 172.22.0.2 | Up 4 weeks |
| gitea | 172.20.0.2 | Up 2 weeks |
| borgwarehouse | — (arrêté) | Exited |
| guacd | — (jamais démarré) | Created |

`homeassistant` et `matterbridge` utilisent le réseau host, donc ils partagent l’IP du Pi (`192.168.1.5`).

---

**User**

blog-wordpress-1 utilise oauth.tregorechecs.fr change à oauth2.tregorechecs.fr

---

**Cursor**

Je cherche où `oauth.tregorechecs.fr` est configuré pour `blog-wordpress-1` sur le Pi.

`KEYCLOAK_URL` pointe vers `oauth.tregorechecs.fr` — je cherche le fichier compose pour le mettre à jour.

Je mets à jour `KEYCLOAK_URL` dans `.env`, puis je recrée le conteneur WordPress.

C’est fait.

- `KEYCLOAK_URL` dans `/mnt/nvme/blog/.env` : `https://oauth2.tregorechecs.fr`
- conteneur `blog-wordpress-1` recréé et redémarré

Vérifie côté Keycloak (`oauth2`) que le client `blog` existe bien, avec la bonne redirect URI WordPress.

---

**User**

l'url oauth2.tregorechecs.fr à changé. regarde la configuration de ticketchess en prod

---

**Cursor**

Je regarde la config OAuth/Keycloak de Ticket Chess en production pour trouver la bonne URL.

Ticket Chess en prod utilise le style datanode-sso (`/oauth/...`), pas Keycloak. Je vérifie le détail pour aligner le blog.

Je vérifie les endpoints SSO et le client `blog` pour aligner le WordPress.

---

**User**

il faut peut être ajouter un client dans le sso

---

**Cursor**

Le client `blog` semble déjà présent — je compare sa config avec celle de Ticket Chess, puis j’aligne WordPress sur les endpoints `/oauth/`.

Le client `blog` existe déjà dans le SSO. Le vrai problème : WordPress construit encore des URLs Keycloak (`/realms/...`) alors que prod utilise `/oauth/...`. J’aligne la config.

PowerShell casse le quoting — j’envoie un script de patch sur le Pi.

Pas besoin d’ajouter un client : **`blog` est déjà dans le SSO**, avec le même secret que WordPress et la redirect `https://tregorechecs.fr/wp-admin/admin-ajax.php?action=openid-connect-authorize`.

Le vrai écart venait des URLs : WordPress construisait encore du Keycloak (`/realms/master/protocol/openid-connect/...`), alors que Ticket Chess prod utilise datanode-sso :

- `https://oauth2.tregorechecs.fr/oauth/authorize`
- `https://oauth2.tregorechecs.fr/oauth/token`
- `https://oauth2.tregorechecs.fr/oauth/userinfo`

C’est corrigé dans `docker-compose.yml` du blog, conteneur recréé, constantes vérifiées. Tu peux retester la connexion sur le blog.

---

**User**

j'ai 
ERROR (invalid-token-response): Invalid token response

https://tregorechecs.fr/wp-login.php?login-error=invalid-token-response&message=Invalid+token+response 

---

**Cursor**

Erreur côté échange de token — je compare la réponse SSO avec ce qu’attend le plugin WordPress.

Le plugin exige `id_token` + `token_type=Bearer`. Je vérifie ce que renvoie réellement le SSO.

Le SSO semble renvoyer un format form-urlencoded plutôt que du JSON OIDC — je confirme.

---

**User**

est-ce que c'est un problème du SSO?

---

**Cursor**

Oui — je confirme rapidement si le SSO renvoie bien du OAuth2 sans `id_token` (ce qu’exige WordPress).

Oui. Le problème vient surtout du **SSO**, pas de la config WordPress.

Le plugin WordPress exige une réponse **OIDC** avec un `id_token` JSON (`token_type=Bearer`). Or datanode-sso ne fournit que du **OAuth2** classique : `access_token` (+ `token_type` / `expires_in`), **sans `id_token`**.

C’est pour ça que Ticket Chess marche (il peut se contenter de `access_token` + `/oauth/userinfo`), alors que le blog échoue avec `invalid-token-response`.

Il faudrait soit faire évoluer le SSO pour renvoyer un `id_token` (scope `openid`), soit adapter le login WordPress pour accepter OAuth2 sans `id_token`.


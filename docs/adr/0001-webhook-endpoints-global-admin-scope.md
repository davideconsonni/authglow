# Webhook Endpoint globali admin-only in v1; scoping per-client rimandato

I Webhook Endpoint registrati in v1 sono globali e gestiti solo dall'admin: ricevono gli
eventi di sistema filtrati per Event Type scelto, senza alcun legame a un Client specifico.
Lo scoping per-client (es. "l'App A vuole solo i propri utenti") è rimandato esplicitamente
a una v2: il dispatcher potrà aggiungere quel filtro senza stravolgere il modello.

## Considered Options

- **Per-client dalla v1**: richiede owner opzionale, semantica di filtro a tempo di emissione
  e domande di autorizzazione (chi registra? il client stesso via DCR?) — complessità ×3 per
  un bisogno non ancora dimostrato.
- **Globali + filtri per tipo** (scelta): copre il caso d'uso reale v1 (notifiche operative)
  con un modello minimale.

## Consequences

- Una volta che integratori esterni consumeranno webhook globali, introdurre lo scoping
  per-client sarà un cambiamento visibile ai consumatori — da pianificare come breaking
  change versionata.

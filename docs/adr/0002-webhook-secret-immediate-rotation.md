# Rotazione del Signing Secret immediata, senza grace period dual-secret

Alla rotazione (`POST …/rotate-secret`) il vecchio secret cessa di valere istantaneamente:
il ricevente deve aggiornare la propria verifica nello stesso momento. Non adottiamo il
dual-secret con finestra di grazia (come consente Stripe) in v1.

## Considered Options

- **Dual-secret con grace period**: zero downtime per il ricevente, ma raddoppia lo stato
  (due segreti attivi + scadenze), complica firma e verifica, e apre domande (quanto dura
  la finestra? chi la decide?). Rinviato a quando ci sarà un consumatore reale che lo chiede.
- **Rotazione immediata** (scelta): un solo secret valido in ogni istante; il disagio di
  coordinamento è documentato e accettato.

## Consequences

- Chi ruota deve aggiornare il proprio endpoint atomicamente: documentarlo nella UI e nella
  reference API.

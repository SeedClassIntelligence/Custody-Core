# Developer accounts and agreement signing

A door opens only after the invited developer has signed its agreement with a key from their own device.

## The flow

1. **Creator** creates a door and presses **Create and invite**. The agreement text is generated from the door
   (parties, project, job, repositories and access, end date, rights type, confidentiality) and fixed: its text and
   SHA-256 are stored on the door and cannot change afterwards (the database refuses). The creator gets a link, shown
   once (only its SHA-256 is stored), valid 7 days or until the door's end date, whichever is first. Custody Core does
   not send emails yet: the creator sends the link. **Send a new link** on the door's page replaces it.
2. **Developer** opens the link, creates an account (or signs in) **with the invited email address**, confirms the
   email, and sets up an authenticator app. This is the same login as creators: Supabase checks the password, and
   Custody Core's own server checks every authenticator code, with the same wrong-code lockout (5 wrong codes in 15
   minutes lock it for 15 minutes; `docs/LOGIN_SETUP.md`). The link works only for an account with that email.
3. The developer reads the agreement, accepts the invitation, types their full name, ticks the consent statement, and
   presses **Sign with this device**. Their browser makes an ECDSA P-256 key pair (once per device). The private half
   is created non-exportable: the browser can sign with it but cannot give it out, so it never leaves the device.
   Only the public half is sent.
4. The server checks the signed statement names exactly this agreement's SHA-256, this door and project, this
   login and email, the consent text, and a time within 10 minutes of the server clock; then checks the signature
   with the developer's registered key. Only then does the door open (the database refuses to open a door without a
   signed agreement).
5. The developer gets their **own** git credential (shown once; getting a new one ends the old one). The creator
   never sees it.

Every step is in the project's tamper-evident record: `door.invited`, `door.invite_accepted`, `agreement.signed`,
`door.opened`, `credential.issued`. A new device key is recorded on the developer's own account record
(`developer.key_registered`).

## Checking a signature without trusting Custody Core

The `agreement.signed` event holds everything needed: `signed_statement` (the exact bytes signed, UTF-8 JSON),
`signature` (base64, the 64-byte r‖s form browsers produce), and `public_key_spki` (base64 DER). The statement's
`agreement_sha256` is the SHA-256 of the agreement text (the creator can read the text on the door's page).

```
echo "<public_key_spki>" | base64 -d > key.der
openssl pkey -pubin -inform DER -in key.der -out key.pem
printf '%s' '<signed_statement>' > statement.json
# openssl expects DER signatures; convert r||s (64 bytes) to DER, e.g. with this one-liner:
python3 -c "import base64,sys;s=base64.b64decode(sys.argv[1]);i=lambda b:(b'\x00'+b if b[0]>127 else b).lstrip(b'\x00') or b'\x00';r,t=i(s[:32]),i(s[32:]);r=(b'\x00'+r) if r[0]>127 else r;t=(b'\x00'+t) if t[0]>127 else t;body=b'\x02'+bytes([len(r)])+r+b'\x02'+bytes([len(t)])+t;open('sig.der','wb').write(b'\x30'+bytes([len(body)])+body)" "<signature>"
openssl dgst -sha256 -verify key.pem -signature sig.der statement.json      # prints: Verified OK
```

## What this proves, and what it does not

- It proves the holder of that device key, signed in to the invited account (password plus authenticator code),
  agreed to the agreement with that exact SHA-256, at that time, under the typed name, with the consent statement.
- It does not prove legal identity: nobody checked an ID document. The account is tied to an email address and an
  authenticator app, and the key to a device.
- The agreement texts are a plain template (`server/agreements.ts`), not legal advice. Have a lawyer review them for
  your jurisdiction before relying on them; payment and other terms are agreed separately.
- Whether such an electronic signature is enforceable depends on the law that applies. US and EU law generally accept
  electronic signatures given with intent and consent, with the record kept; some kinds of documents need more.
  That is a question for your lawyer, not something this code can settle.

## Paid e-signature services

None is needed for the signing above. A service such as DocuSign, Dropbox Sign, BoldSign or Documenso adds a
recognizable brand for the other party, its own audit certificate, optional ID checks (at extra cost), and its own
legal backing. It would sit next to this signature, not replace it: the door would still open on the key signature
recorded here.

## Not built yet

- Sending invitation emails (the creator sends the link).
- Creator-written or lawyer-supplied agreement templates (the built-in ones are fixed).
- Signing with an existing SSH or hardware key instead of a browser key.

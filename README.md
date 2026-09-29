# Break365

Private betting board for how long couples will last: **+Weeks** (ends before 3 months), **+Months** (3 to 12 months), **+Years** (1 year or more). Static site for GitHub Pages.

## Files

| File | What it is |
|---|---|
| `index.html`, `style.css`, `app.js` | The site |
| `keyring.json` | Encrypted keys. No passwords inside |
| `couples.enc.json` | The couples list, encrypted (starts empty) |
| `tools/keytool.mjs` | Optional: change passwords |

Players never touch GitHub or anything technical: they open the site and type the player password.

## Deploy (5 minutes)

1. GitHub: **New repository**, e.g. `break365`. On the Free plan it must be **Public** for Pages to work. That is fine: every data file is encrypted.
2. **Add file > Upload files**: upload all files above, keeping the `tools` folder. Commit.
3. **Settings > Pages**: Source **Deploy from a branch**, branch `main`, folder `/ (root)`. Save.
4. After about 1 minute the site is at `https://<your-user>.github.io/break365/`.

## Logging in

- Admin password: adds, edits, settles and deletes couples, sets betting links.
- User password: sees the board and bet slip only.

## One-time setup: automatic publishing (site owner, 3 minutes)

Do this once. Afterwards any admin only needs the admin password: every change publishes by itself.

1. GitHub: your profile picture > **Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token**.
2. Name `break365`. Expiration: the longest you are comfortable with (when it expires, admins see a clear message and you repeat this setup).
3. **Repository access: Only select repositories** > this repository.
4. **Permissions > Repository permissions > Contents: Read and write**. Nothing else.
5. Generate, copy the token.
6. Log in to Break365 with the admin password > **Admin** tab > bottom, **GitHub connection**. Username and repository are prefilled when the site runs on GitHub Pages. Paste the token > **Connect GitHub**.

The connection is saved inside `keyring.json`, encrypted with the admin password. The player password cannot open it, and the token is never visible in any file.

## Adding couples (admin, no technical steps)

1. Log in with the admin password, open **Admin**.
2. Add, edit, settle or delete couples. Each change is published automatically; the bar at the top says **All changes published**.
3. Players see it within 1 to 2 minutes (the time GitHub Pages takes to update).

If something fails (no internet, token expired), the bar says what happened and shows **Try again**. Several admins can edit at the same time: each change is merged with the latest version, so nobody overwrites anyone.

To settle a couple: **Edit**, set Status to *Broken up*, pick the date, save. The winning option is computed automatically. Options a live couple has already outlasted show as *Closed*.

Without the GitHub connection, changes stay in the browser tab; **Manual backup** at the bottom downloads the encrypted file to upload by hand.

## Betting, live % and odds (Manifold)

Bets are placed on **Manifold Markets** (manifold.markets): free, play money only (mana), no real cash. Each player needs a free Manifold account.

For each couple:

1. On Manifold, create a **multiple-choice** market with exactly three answers: **Weeks**, **Months**, **Years** (Semanas, Meses, Años also work). Use nicknames in the title, not real names.
2. Copy the market link, e.g. `https://manifold.markets/yourname/market-name`.
3. In Break365 Admin, paste it as the couple's betting link and press **Check Manifold market**. It shows the current % per option if everything is right, or tells you what to fix.
4. Save. It is published automatically.

What players then see on that couple's card, refreshed every 60 seconds:

- the % of the Manifold market on each option,
- odds calculated from it: `odds = (1 − house margin) ÷ probability` (40% with 0 margin gives 2.50; set the margin in Admin, Betting settings),
- number of bettors and total volume,
- a **Place bet on manifold.markets** button that opens the market.

If Manifold can't be reached, the card says so and shows the house odds the admin entered, or the last good numbers if it worked before. Couples without a Manifold link always use house odds.

Privacy of this part: the page only asks Manifold's public API for the market's short name (no login, no cookies, no referrer). The bets themselves live on Manifold, where anyone with the market link can see them.

## Privacy and security, precisely

- No password is in any file. Each password goes through PBKDF2-SHA256 (600,000 iterations, random salt) to unwrap a random AES-256-GCM data key. The couples file is encrypted with that key.
- Checking the password and decrypting happen only in the browser. The password is never sent anywhere; the page loads no external scripts, fonts or trackers, and may only contact GitHub (when the admin publishes) and Manifold's API (enforced by a Content-Security-Policy).
- Search engines are told not to index the page. Links to the betting site send no referrer.
- The GitHub token is stored only inside `keyring.json`, encrypted with a key derived from the admin password. It can write only to this repository's files. Anyone who knew the admin password could use it, so the admin password should stay among admins.
- Limits of any static site: someone who has the site URL can try to guess the passwords offline. The slow key derivation makes each guess expensive, so long passwords matter. Anyone who ever logged in with the user password can read the data; share it only with the group.

## Changing passwords (optional)

Needs Node 18+. In a local copy of the repo:

```
node tools/keytool.mjs rotate
```

It asks for a current password and the two new ones (hidden input), creates a new data key, re-encrypts the couples and rewrites `keyring.json` and `couples.enc.json`. Upload both files. Old passwords stop working for the new files. Give the current **admin** password to keep the GitHub connection; with the player password you will need to connect GitHub again.

## Test locally

WebCrypto needs a web server, not a double-clicked file:

```
python3 -m http.server 8000
```

then open `http://localhost:8000`.

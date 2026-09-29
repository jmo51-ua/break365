# Break365

Private betting board on how long couples will last. Players make their own bets (**+4 months**, **−3 weeks**, **will they marry?**) and the odds move with every bet, like Twitch predictions. Static site for GitHub Pages; everything is encrypted.

Players never touch GitHub: they open the site, type the player password, pick a name and a PIN, and bet.

## Files

| File | What it is |
|---|---|
| `index.html`, `style.css`, `app.js` | The site |
| `keyring.json` | Encrypted keys (no passwords inside) |
| `couples.enc.json` | The couples list, encrypted |
| `tools/keytool.mjs` | Optional: change passwords |

When **updating** a live site, upload only `index.html`, `style.css`, `app.js`, `README.md` and `tools/`. Never overwrite `keyring.json` or `couples.enc.json`: that would erase your couples and connections.

## How betting works

- Everyone starts with the same points (1,000 by default, set in Admin > Points).
- A **line** is a time counted from the day the couple got together: 3 weeks, 4 months, 2 years... Any player can create one with **Make your own bet**.
- Each line has two sides:
  - **+** they are still together after that date,
  - **−** they break up on or before it.
- **Marriage** is a line too: **Yes** they get married, **No** they break up without marrying.
- **Odds** of a side = all points on the line ÷ points on that side. Example: 100 on +4 months and 300 on −4 months: + pays 4.00, − pays 1.33.
- When a line is decided, the winning side splits all the points on that line, in proportion to what each person bet.
- If nobody took the other side, winners just get their points back. So pick lines other people are already betting on (the most popular ones are shown first on each couple).
- One side per line per player. You can add more points to your side, and bet on as many lines as you like.

Lines are decided automatically from the dates the admin enters:

- A **+** line wins as soon as they are still together the day after its date.
- When the admin marks the couple as broken up, every open line is decided: **−** wins if the break-up date is on or before the line date.
- **Marriage: Yes** wins when the admin ticks "They got married". **No** wins when they break up unmarried.
- Bets placed on or after the day that decided a line are refunded (so nobody profits from news before the admin updates the couple).
- Deleting a couple cancels its bets and returns the points.

## One-time setup (site owner, about 10 minutes)

### 1. Automatic publishing (site repository)

1. GitHub: profile picture > **Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token**.
2. **Repository access: Only select repositories** > the site repository.
3. **Permissions > Repository permissions > Contents: Read and write**. Nothing else. Generate and copy.
4. Break365 > log in as admin > **Admin** > bottom, **GitHub connection** > paste > **Connect GitHub**.

This token is saved encrypted with the admin password. The player password cannot open it.

### 2. Bets storage (a separate private repository)

1. GitHub: **New repository**, e.g. `break365-bets`, **Private**, tick **Add a README file**. Create.
2. Create a **second** fine-grained token exactly as above, but with access **only to `break365-bets`**, Contents: Read and write.
3. Break365 > **Admin** > **Bets storage**: username, repository `break365-bets`, branch `main`, paste the second token > **Connect bets storage**.

The page refuses a public repository, the site repository, or the admin token here. This token is used by players' browsers, which is why it must only reach the bets repository.

## Admin, day to day

- **Add couple**: names and the date they got together. No odds to set.
- **Broke up**: Edit > Status *Broken up* > date > save. Lines are decided and points paid out automatically.
- **Married**: Edit > tick *They got married* > date > save.
- Every change publishes by itself; the bar at the top says **All changes published**.
- On a couple's bet list, **×** deletes a bet (points go back). In **Ranking**, **Reset PIN** lets a player who forgot their PIN choose a new one (points and bets stay).

## Players

1. Open the site, type the player password.
2. Tap a side of an existing line, or **Make your own bet**: choose **+ More than** or **− Less than**, the number and weeks, months or years (or the Marriage tab).
3. First time: pick a name and a 4 to 8 digit PIN. The device remembers it; use the same name and PIN on other devices.
4. Choose the stake and **Place bet**. Odds on every card update every 10 seconds.
5. **Ranking** shows everyone's points.

## Privacy and security

- No password is in any file. Passwords unlock the keys only inside the browser (PBKDF2-SHA256, 600,000 iterations, AES-256-GCM).
- Couples: `couples.enc.json` in the site repository, encrypted.
- Bets and player names: `bets.enc.json` in the private bets repository, encrypted with a key that is itself stored inside the encrypted couples file. PINs are stored only as salted hashes.
- The page loads nothing from other sites and may only talk to `api.github.com` (enforced by a Content-Security-Policy). Search engines are told not to index it.
- Limits, honestly: anyone with the player password can read the board and, with technical skills, could extract the bets token and edit the bets file directly (GitHub keeps every version, so it can be undone). PINs stop casual impersonation, not a determined programmer. The admin password can publish to the site, so keep it among admins.

## Changing passwords (optional)

Needs Node 18+. In a local copy of the repository:

```
node tools/keytool.mjs rotate
```

Give the current **admin** password to keep the GitHub connection. It re-encrypts the couples (including the bets key, so existing bets stay readable) and rewrites `keyring.json` and `couples.enc.json`. Upload both.

## Test locally

```
python3 -m http.server 8000
```

then open `http://localhost:8000`.

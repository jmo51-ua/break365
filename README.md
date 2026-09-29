# Break365

Private betting board on how long couples will last. Players make their own bets (**+4 months**, **−3 weeks**, **Married**) and the odds move with every bet, like Twitch predictions. Static site for GitHub Pages; everything is encrypted.

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

- Bets are in **€** (play money, nothing is ever paid) and **unlimited**: bet as much as you like (up to €1,000,000 per bet). The **Ranking** is by profit: money won minus money lost.
- A player picks one of three bets on a couple:
  - **+ Together**: they stay together for at least X weeks, months or years (the player chooses X),
  - **− Together**: they break up in less than X weeks, months or years (the player chooses X),
  - **Married**: they get married.
- All bets on a couple go into **one pot**. When the couple is settled, everyone who got it right gets their stake back plus a share of the wrong bets, in proportion to what they bet.
  Example: €100 on +4 months, €300 on −4 months, €100 on Married. They break up after 2 months: only −4 months is right, so its bettors get their €300 back plus the €200 from the others (×1.67).
- Each bet shows its money, its share of the pot and **up to ×**: the most each euro can return if it comes true, given the bets so far. It changes live as people bet.
- You can place as many bets as you like, but not **+** and **−** for the same time.
- If nobody got it right, everyone gets their money back.

When the couple is settled (the admin records it with **Edit**):

- **Break-up**: every **+X** whose date is after the break-up wins, every **−X** whose date is on or after it wins, **Married** loses.
- **Wedding**: **Married** and every **+** bet win, every **−** bet loses. The couple moves to **Settled**.
- A **+X** or **−X** can only be placed while its date is still in the future. Once the date passes, the card shows it as already true or lost; winnings are paid when the couple is settled.
- Bets placed on or after the break-up or wedding day are refunded (so nobody profits from news before the admin updates the couple).
- Deleting a couple cancels its bets and returns the money.

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

- **Add couple**: Name 1, Name 2 and the date they started dating, typed as **DD/MM/YYYY** (just typing the 8 digits fills in the slashes). Nothing else.
- **Broke up**: Edit > Status *Broken up* > date (DD/MM/YYYY) > save. Bets are settled and winnings paid out automatically.
- **Married**: Edit > tick *They got married* > date (DD/MM/YYYY) > save.
- Every change publishes by itself; the bar at the top says **All changes published**.
- On a couple's bet list, **×** deletes a bet (the money goes back). In **Ranking**, **Reset PIN** lets a player who forgot their PIN choose a new one (their money and bets stay).

## Players

1. Open the site, type the player password.
2. Press **Make your bet** on a couple (or tap a bet someone already made): choose **+ Together**, **− Together** or **Married**; for + and − also pick the number and weeks, months or years.
3. First time: pick a name and a 4 to 8 digit PIN. The device remembers it; use the same name and PIN on other devices.
4. Choose the stake in € and **Place bet**. Odds on every card update every 10 seconds.
5. **Ranking** shows everyone's profit.

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

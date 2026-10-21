# ⚡ Corsly - Fast & Secure Public CORS Proxy

පූර්ණ CORS Support, IP-based Rate Limiting (15 req/hr, 89 req/day), සහ 26-hour KV TTL සහිත Cloudflare Workers සඳහාම සකසන ලද Public Cross-Origin Proxy එකකි.

---

## 🌟 Features (විශේෂාංග)

- **CORS Support**: ඕනෑම API හෝ Web Request එකක් CORS block නොවී browser එකෙන් call කිරීමේ හැකියාව (`Access-Control-Allow-Origin: *`).
- **IP Rate Limiting**:
  - **පැයට requests 15 යි** (15 requests / hour per IP)
  - **දවසට requests 89 යි** (89 requests / day per IP)
- **Cloudflare KV Integration**: Namespace ID `fa973f0ae1114355a327b3ecf2b6006a` මගින් edge-wide distributed rate tracking.
- **26-Hour KV TTL**: සෑම IP එකක්ම KV එකේ save වී පවතින්නේ හරියටම **පැය 26ක්** පමණි (`expirationTtl: 93600`). පැය 26කට පසු inactive IP data ස්වයංක්‍රීයව KV එකෙන් delete වේ.
- **Smart Preflight (OPTIONS)**: Browsers යවන CORS `OPTIONS` preflight requests rate limit quota එකෙන් අඩු නොවී ක්ෂණිකව allow කරනු ලැබේ.
- **SSRF & Loop Protection**: Private IP ranges (127.0.0.1, 10.x, 192.168.x, 169.254.x Cloud metadata) සහ worker එකටම loop වෙන requests block කරනු ලැබේ.
- **Dual Syntax**: `?url=https://...` මෙන්ම `/https://...` ආකාර දෙකටම සහය දක්වයි.
- **Built-in Web Playground**: Worker එකේ URL එක browser එකෙන් open කළ විට ලස්සන UI එකක් සහ live request tester එකක් ලැබේ.
- **`/quota` Endpoint**: Rate limit count එක වැඩි නොවී ඉතිරි quota එක බලාගැනීමේ හැකියාව.

---

## 🛠️ ක්‍රම 2 කින් Deploy කළ හැක (Deployment Guide)

### ක්‍රමය 1: Cloudflare Dashboard එකෙන් Direct Deploy කිරීම (ලේසිම ක්‍රමය)

1. [Cloudflare Dashboard](https://dash.cloudflare.com/) එකට login වී **Workers & Pages** වෙත යන්න.
2. **Create application** > **Create Worker** click කර නමක් ලබාදී **Deploy** කරන්න.
3. Deploy වූ පසු **Edit code** (Quick Edit) click කරන්න.
4. එහි ඇති code එක මකා මෙහි ඇති `worker.js` එකේ සම්පූර්ණ code එක copy කර paste කර **Save and deploy** කරන්න.
5. **KV Binding එක සම්බන්ධ කිරීම (අනිවාර්යයි)**:
   - Worker එකේ **Settings** > **Variables and Secrets** (හෝ **KV Namespace Bindings**) වෙත යන්න.
   - **KV Namespace Bindings** යටතේ **Add binding** click කරන්න.
   - **Variable name**: `RATE_LIMIT_KV` (හරියටම මේ අකුරින්ම ලබාදෙන්න)
   - **KV namespace**: ඔයාගේ KV ID එක වන `fa973f0ae1114355a327b3ecf2b6006a` තෝරා **Save and deploy** කරන්න.

---

### ක්‍රමය 2: Wrangler CLI මගින් Deploy කිරීම

1. Dependencies install කරගන්න:
   ```bash
   npm install
   ```

2. Local එකේ test කර බැලීමට:
   ```bash
   npm run dev
   ```

3. Cloudflare එකට deploy කිරීමට:
   ```bash
   npx wrangler login
   npm run deploy
   ```

---

## 📖 Proxy එක භාවිතා කරන ආකාරය (Usage Examples)

ඔයාගේ Worker URL එක `https://my-cors-proxy.yourname.workers.dev` යැයි සිතමු.

### 1. Query Parameter මගින් (වඩාත් නිර්දේශිතයි):
```http
GET https://my-cors-proxy.yourname.workers.dev/?url=https://api.github.com/users/octocat
```

### 2. Path-based මගින්:
```http
GET https://my-cors-proxy.yourname.workers.dev/https://api.github.com/users/octocat
```

---

## 💻 Code වලට Integrate කරන ආකාරය

### JavaScript / Frontend (Fetch API)
```javascript
const targetApi = 'https://api.github.com/users/octocat';
const proxyUrl = 'https://my-cors-proxy.yourname.workers.dev/?url=' + encodeURIComponent(targetApi);

fetch(proxyUrl)
  .then(res => {
    // Rate limit headers කියවා ගත හැක
    console.log('Hourly Remaining:', res.headers.get('X-RateLimit-Remaining-Hour'));
    console.log('Daily Remaining:', res.headers.get('X-RateLimit-Remaining-Day'));
    return res.json();
  })
  .then(data => console.log('Data:', data))
  .catch(err => console.error('Error:', err));
```

### cURL
```bash
curl -i "https://my-cors-proxy.yourname.workers.dev/?url=https://api.github.com/users/octocat"
```

### Python
```python
import requests

target_url = "https://api.github.com/users/octocat"
proxy = f"https://my-cors-proxy.yourname.workers.dev/?url={target_url}"

res = requests.get(proxy)
print("Status:", res.status_code)
print("Remaining this hour:", res.headers.get("X-RateLimit-Remaining-Hour"))
print("Data:", res.json())
```

---

## 📊 Rate Limit Headers

Proxy එක හරහා යන සෑම response එකකම පහත Headers අන්තර්ගත වේ:

| Header Name | විස්තරය |
|---|---|
| `X-RateLimit-Limit-Hour` | පැයට ලබාදී ඇති උපරිම request ප්‍රමාණය (`15`) |
| `X-RateLimit-Remaining-Hour` | මෙම පැය තුළ තව ඉතිරිව ඇති request ප්‍රමාණය |
| `X-RateLimit-Limit-Day` | දිනකට ලබාදී ඇති උපරිම request ප්‍රමාණය (`89`) |
| `X-RateLimit-Remaining-Day` | අද දින තුළ තව ඉතිරිව ඇති request ප්‍රමාණය |
| `X-RateLimit-Client-IP` | Request එක එවූ Client ගේ IP ලිපිනය |
| `Retry-After` | (Rate limit වූ විට පමණක්) නැවත try කිරීමට ඉතිරිව ඇති තත්පර ගණන |

---

## 🚦 Quota Exceeded Response (HTTP 429)

IP එකක් පැයට 15 සීමාව හෝ දවසට 89 සීමාව ඉක්මවූ විට ලැබෙන JSON response එක:

```json
{
  "error": "Too Many Requests",
  "message": "Hourly rate limit exceeded (15 requests/hour). Please try again in 1840 seconds.",
  "clientIp": "203.0.113.195",
  "limit": 15,
  "period": "hourly",
  "remainingHour": 0,
  "remainingDay": 73,
  "retryAfterSeconds": 1840
}
```

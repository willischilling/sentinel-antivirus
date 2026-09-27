// Reviews (stars + comments), stored in Supabase. The URL and the publishable key are
// meant to be public: the database only lets visitors read visible reviews and add new
// ones, with limits (see supabase/reviews.sql). Leave them empty to turn reviews off.
const REVIEWS = {
  url: "https://pgjrtfzzgamsxyzaiygn.supabase.co",
  key: "sb_publishable_XC1gZrik08y1yvegrTfgDg_7YJwC_M5",
};

const Reviews = (() => {
  const on = Boolean(REVIEWS.url && REVIEWS.key);
  const headers = () => {
    const h = { apikey: REVIEWS.key, "Content-Type": "application/json" };
    if (REVIEWS.key.startsWith("eyJ")) h.Authorization = "Bearer " + REVIEWS.key;  // older "anon" keys
    return h;
  };
  async function call(path, options = {}) {
    const res = await fetch(REVIEWS.url.replace(/\/$/, "") + "/rest/v1/" + path, { ...options, headers: headers() });
    if (!res.ok) {
      let message = "Something went wrong. Try again later.";
      try { const body = await res.json(); if (body && body.message) message = body.message; } catch (_) {}
      throw new Error(message);
    }
    return res.status === 201 || res.status === 204 ? null : res.json();
  }
  return {
    on,
    async stats() {
      const rows = await call("review_stats?select=*");
      return rows[0] || { count: 0, average: 0 };
    },
    list(limit = 100) {
      return call(`reviews?select=id,created_at,name,stars,comment&order=created_at.desc&limit=${limit}`);
    },
    post(name, stars, comment) {
      return call("reviews", {
        method: "POST",
        body: JSON.stringify({ name: (name || "").trim().slice(0, 40) || "Anonymous", stars,
                               comment: (comment || "").trim().slice(0, 600) || null }),
      });
    },
    starText(n) { return "★".repeat(n) + "☆".repeat(5 - n); },
  };
})();

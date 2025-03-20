require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const axios = require("axios");
const Stripe = require("stripe");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// 🔹 Discord OAuth Strategy
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_REDIRECT_URI,
  scope: ["identify", "guilds", "guilds.members.read"]
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Fetch user roles from Discord
    const response = await axios.get(
      `https://discord.com/api/guilds/${process.env.DISCORD_GUILD_ID}/members/${profile.id}`,
      { headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}` } }
    );

    const userRoles = response.data.roles;
    const isPaidMember = userRoles.includes(process.env.DISCORD_PAID_ROLE_ID);

    if (!isPaidMember) return done(null, false);
    return done(null, profile);
  } catch (error) {
    return done(error, false);
  }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// 🔹 Discord Login Route
app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/callback", passport.authenticate("discord", { failureRedirect: "/" }), (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
});

// 🔹 Secure Dashboard Route
app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ message: "Unauthorized" });
  res.json({ user: req.user });
});

// 🔹 Stripe Checkout Session
app.post("/create-checkout-session", async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      success_url: "https://your-backend.onrender.com/payment-success?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: process.env.FRONTEND_URL,
      line_items: [{ price: "your_stripe_price_id", quantity: 1 }],
    });

    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🔹 Payment Success → Redirect to Discord
app.get("/payment-success", (req, res) => {
  res.redirect("https://discord.gg/YOUR_INVITE_LINK");
});

// 🔹 Assign Discord Role via Webhook
app.post("/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const customerEmail = event.data.object.customer_details.email;
    const discordId = await getDiscordIdFromEmail(customerEmail);
    
    if (discordId) {
      await assignDiscordRole(discordId);
    }
  }

  res.json({ received: true });
});

// 🔹 Assign Role Function
async function assignDiscordRole(userId) {
  try {
    await axios.put(
      `https://discord.com/api/guilds/${process.env.DISCORD_GUILD_ID}/members/${userId}/roles/${process.env.DISCORD_PAID_ROLE_ID}`,
      {},
      { headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}` } }
    );
    console.log(`✅ Assigned Paid Role to ${userId}`);
  } catch (error) {
    console.error("❌ Error assigning role:", error.message);
  }
}

app.listen(3001, () => console.log("Backend running on port 3001"));

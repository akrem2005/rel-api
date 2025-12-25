// app.js - Full Updated Real Estate App API with Subscriptions
// Node.js + Express + MySQL
// Features: Agent credits, Hotel revenue share or monthly fee, Free trial months

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();
const port = 3000;

app.use(express.json());
app.use("/uploads", express.static("uploads"));

// === Create uploads folder if it doesn't exist ===
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
  console.log("Created 'uploads' directory");
}

// === Multer Configuration with Proper Filenames & Extensions ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    // Sanitize and create unique filename with original extension
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    // Replace spaces and special chars with underscores
    const safeName = basename.replace(/[^a-zA-Z0-9]/g, "_");
    const uniqueName = `${safeName}-${Date.now()}${ext.toLowerCase()}`;
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max per file
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      cb(null, true);
    } else {
      cb(
        new Error("Only image files (jpeg, jpg, png, gif, webp) are allowed!")
      );
    }
  },
});

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Access Denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid Token" });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admin access required" });
  next();
};

const ownerMiddleware = async (req, res, next) => {
  const [rows] = await pool.query(
    "SELECT ownerId FROM properties WHERE id = ?",
    [req.params.id]
  );
  if (rows.length === 0 || rows[0].ownerId !== req.user.id) {
    return res.status(403).json({ error: "Not the owner" });
  }
  next();
};

const subscriptionMiddleware = async (req, res, next) => {
  if (req.user.role === "user" || req.user.role === "admin") return next();

  try {
    const [subs] = await pool.query(
      `SELECT us.*, sp.listing_credits, sp.price_per_month, sp.revenue_share_percent, sp.free_months
       FROM user_subscriptions us
       JOIN subscription_plans sp ON us.planId = sp.planId
       WHERE us.userId = ? AND us.is_active = TRUE
       LIMIT 1`,
      [req.user.id]
    );

    if (subs.length === 0) {
      return res
        .status(403)
        .json({ error: "No active subscription. Please contact admin." });
    }

    const sub = subs[0];
    const today = new Date();
    const start = new Date(sub.start_date);

    if (sub.end_date && new Date(sub.end_date) < today) {
      return res.status(403).json({ error: "Subscription expired." });
    }

    req.subscription = sub;

    if (
      req.user.role === "agent" &&
      req.method === "POST" &&
      req.originalUrl === "/api/properties"
    ) {
      if (sub.credits_remaining <= 0) {
        return res
          .status(403)
          .json({ error: "No listing credits remaining. Purchase more." });
      }
    }

    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// 1. Authentication
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password, role = "user" } = req.body;
  if (!["user", "agent", "hotel", "admin"].includes(role))
    return res.status(400).json({ error: "Invalid role" });

  try {
    const [existing] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (existing.length > 0)
      return res.status(400).json({ error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashed, role]
    );

    const token = jwt.sign(
      { id: result.insertId, role },
      process.env.JWT_SECRET
    );
    res.json({
      token,
      user: { id: result.insertId, name, email, role },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0)
      return res.status(400).json({ error: "Invalid credentials" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET
    );
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Property Management - LIST ALL
app.get("/api/properties", async (req, res) => {
  let query = "SELECT * FROM properties WHERE 1=1";
  const params = [];
  const filters = [
    "category",
    "listingType",
    "minPrice",
    "maxPrice",
    "minArea",
    "bedrooms",
    "bathrooms",
    "search",
    "isVerified",
  ];

  filters.forEach((f) => {
    if (req.query[f]) {
      if (f === "minPrice") query += " AND price >= ?";
      else if (f === "maxPrice") query += " AND price <= ?";
      else if (f === "minArea") query += " AND area >= ?";
      else if (f === "search") query += " AND (name LIKE ? OR location LIKE ?)";
      else query += ` AND ${f} = ?`;
      if (f === "search") params.push(`%${req.query[f]}%`, `%${req.query[f]}%`);
      else params.push(req.query[f]);
    }
  });

  try {
    const [rows] = await pool.query(query, params);

    // Format image URLs for all properties
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const formattedProperties = rows.map((prop) => {
      let images = [];
      if (prop.images) {
        try {
          const parsed = JSON.parse(prop.images);
          images = parsed.map((img) => `${baseUrl}/uploads/${img}`);
        } catch (e) {}
      }
      return { ...prop, images };
    });

    res.json(formattedProperties);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET SINGLE PROPERTY
app.get("/api/properties/:id", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM properties WHERE id = ?", [
      req.params.id,
    ]);
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });

    const baseUrl = `${req.protocol}://${req.get("host")}`;
    let images = [];
    if (rows[0].images) {
      try {
        const parsed = JSON.parse(rows[0].images);
        images = parsed.map((img) => `${baseUrl}/uploads/${img}`);
      } catch (e) {}
    }

    res.json({ ...rows[0], images });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CREATE PROPERTY
app.post(
  "/api/properties",
  authMiddleware,
  subscriptionMiddleware,
  upload.array("images", 10),
  async (req, res) => {
    const {
      name,
      user_id,
      location,
      price,
      description,
      category,
      listingType,
      bedrooms,
      bathrooms,
      area,
      furnishingStatus,
      floorNumber,
      parkingSpaces,
      maxGuests,
      roomQuota = 0,
    } = req.body;

    if (!name || !location || !user_id || !price || !category || !listingType) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const images = req.files ? req.files.map((f) => f.filename) : [];
    const imagesJson = JSON.stringify(images);

    const ownerId = req.user.id;
    const isVerified = ["admin", "agent", "hotel"].includes(req.user.role)
      ? 1
      : 0;

    try {
      if (req.user.role === "agent") {
        if (req.subscription.credits_remaining <= 0) {
          return res
            .status(403)
            .json({ error: "No listing credits remaining" });
        }

        const newCredits = req.subscription.credits_remaining - 1;
        await pool.query(
          "UPDATE user_subscriptions SET credits_remaining = ? WHERE id = ?",
          [newCredits, req.subscription.id]
        );
      }

      const [result] = await pool.query(
        `INSERT INTO properties 
        (name, location, price, user_id, description, category, listingType, bedrooms, bathrooms, area, images,
         furnishingStatus, floorNumber, parkingSpaces, maxGuests, roomQuota, ownerId, isVerified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          name,
          location,
          price,
          user_id,
          description || null,
          category,
          listingType,
          bedrooms || null,
          bathrooms || null,
          area || null,
          imagesJson,
          furnishingStatus || null,
          floorNumber || null,
          parkingSpaces || null,
          maxGuests || null,
          roomQuota,
          ownerId,
          isVerified,
        ]
      );

      const [newPropertyRows] = await pool.query(
        "SELECT * FROM properties WHERE id = ?",
        [result.insertId]
      );

      const baseUrl = `${req.protocol}://${req.get("host")}`;
      let formattedImages = [];
      if (newPropertyRows[0].images) {
        try {
          const parsed = JSON.parse(newPropertyRows[0].images);
          formattedImages = parsed.map((img) => `${baseUrl}/uploads/${img}`);
        } catch (e) {}
      }

      const newProperty = {
        ...newPropertyRows[0],
        images: formattedImages,
      };

      res.status(201).json({
        message: "Property created successfully",
        property: newProperty,
      });
    } catch (err) {
      console.error("Error creating property:", err);
      res.status(500).json({ error: "Server error: " + err.message });
    }
  }
);

// UPDATE PROPERTY (basic version - you can expand later)
app.put(
  "/api/properties/:id",
  authMiddleware,
  ownerMiddleware,
  upload.array("images", 10),
  async (req, res) => {
    // You can implement full update logic here later
    // For now, return a placeholder
    res
      .status(501)
      .json({ message: "Update endpoint not fully implemented yet" });
  }
);

// DELETE PROPERTY
app.delete(
  "/api/properties/:id",
  authMiddleware,
  ownerMiddleware,
  async (req, res) => {
    try {
      const [prop] = await pool.query(
        "SELECT images FROM properties WHERE id = ?",
        [req.params.id]
      );

      if (prop.length > 0 && prop[0].images) {
        const images = JSON.parse(prop[0].images);
        images.forEach((img) => {
          const filePath = path.join(__dirname, "uploads", img);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        });
      }

      await pool.query("DELETE FROM properties WHERE id = ?", [req.params.id]);
      res.json({ message: "Property deleted successfully" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.get("/api/properties/my-listings", authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM properties WHERE ownerId = ?",
      [req.user.id]
    );

    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const formatted = rows.map((prop) => {
      let images = [];
      if (prop.images) {
        try {
          const parsed = JSON.parse(prop.images);
          images = parsed.map((img) => `${baseUrl}/uploads/${img}`);
        } catch (e) {}
      }
      return { ...prop, images };
    });

    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === Remaining endpoints unchanged (Bookings, Favorites, etc.) ===
app.post("/api/bookings", authMiddleware, async (req, res) => {
  const { propertyId, checkInDate, checkOutDate, guestsCount, paymentMethod } =
    req.body;
  const userId = req.user.id;

  try {
    const [prop] = await pool.query("SELECT * FROM properties WHERE id = ?", [
      propertyId,
    ]);
    if (prop.length === 0)
      return res.status(404).json({ error: "Property not found" });
    const property = prop[0];

    if (property.category === "Hotel" && property.roomQuota > 0) {
      const [overlap] = await pool.query(
        `SELECT COUNT(*) as count FROM bookings 
         WHERE propertyId = ? AND NOT (checkOutDate <= ? OR checkInDate >= ?)`,
        [propertyId, checkInDate, checkOutDate]
      );
      if (overlap[0].count >= property.roomQuota) {
        return res
          .status(400)
          .json({ error: "No rooms available for selected dates" });
      }
    }

    const [bookingResult] = await pool.query(
      "INSERT INTO bookings (propertyId, userId, checkInDate, checkOutDate, guestsCount, paymentMethod) VALUES (?, ?, ?, ?, ?, ?)",
      [
        propertyId,
        userId,
        checkInDate,
        checkOutDate,
        guestsCount,
        paymentMethod,
      ]
    );

    const [sub] = await pool.query(
      "SELECT sp.revenue_share_percent FROM user_subscriptions us JOIN subscription_plans sp ON us.planId = sp.planId WHERE us.userId = ? AND us.is_active = TRUE",
      [property.ownerId]
    );

    if (sub.length > 0 && sub[0].revenue_share_percent > 0) {
      const percent = sub[0].revenue_share_percent;
      const commission = (property.price * percent) / 100;

      await pool.query(
        "INSERT INTO booking_commissions (bookingId, hotelId, commission_amount, percentage) VALUES (?, ?, ?, ?)",
        [bookingResult.insertId, property.ownerId, commission, percent]
      );
    }

    await pool.query(
      "INSERT INTO notifications (userId, message) VALUES (?, ?)",
      [property.ownerId, `New booking for ${property.name}`]
    );

    res.status(201).json({ message: "Booking successful" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Keep the rest of your endpoints (favorites, profile, subscriptions, admin, etc.)
// They remain the same as in your original code.

// ... [All other endpoints you already have: favorites, profile, notifications, subscriptions, admin routes, apply, etc.]
app.get("/api/bookings/my-bookings", authMiddleware, async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM bookings WHERE userId = ?", [
    req.user.id,
  ]);
  res.json(rows);
});

app.get("/api/bookings/my-properties", authMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    `SELECT b.* FROM bookings b JOIN properties p ON b.propertyId = p.id WHERE p.ownerId = ?`,
    [req.user.id]
  );
  res.json(rows);
});

// 4. Favorites (unchanged)
app.get("/api/favorites", authMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    `SELECT p.* FROM properties p JOIN favorites f ON p.id = f.propertyId WHERE f.userId = ?`,
    [req.user.id]
  );
  res.json(rows);
});

app.post("/api/favorites/:propertyId", authMiddleware, async (req, res) => {
  await pool.query(
    "INSERT IGNORE INTO favorites (userId, propertyId) VALUES (?, ?)",
    [req.user.id, req.params.propertyId]
  );
  res.json({ message: "Added to favorites" });
});

app.delete("/api/favorites/:propertyId", authMiddleware, async (req, res) => {
  await pool.query(
    "DELETE FROM favorites WHERE userId = ? AND propertyId = ?",
    [req.user.id, req.params.propertyId]
  );
  res.json({ message: "Removed from favorites" });
});

// 5. Profile & Notifications
app.get("/api/profile", authMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id, name, email, role FROM users WHERE id = ?",
    [req.user.id]
  );
  res.json(rows[0]);
});

app.get("/api/notifications", authMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT * FROM notifications WHERE userId = ? ORDER BY createdAt DESC",
    [req.user.id]
  );
  res.json(rows);
});

// My Subscription
app.get("/api/my-subscription", authMiddleware, async (req, res) => {
  if (["user", "admin"].includes(req.user.role)) return res.json(null);

  const [rows] = await pool.query(
    `SELECT us.credits_remaining, us.payment_status, sp.*
     FROM user_subscriptions us
     JOIN subscription_plans sp ON us.planId = sp.planId
     WHERE us.userId = ? AND us.is_active = TRUE`,
    [req.user.id]
  );
  res.json(rows[0] || null);
});

// Admin: Subscription Plans
app.get(
  "/api/admin/plans",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const [rows] = await pool.query("SELECT * FROM subscription_plans");
    res.json(rows);
  }
);

app.post(
  "/api/admin/plans",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const {
      name,
      role,
      price_per_month = 0,
      revenue_share_percent = 0,
      listing_credits = 0,
      free_months = 0,
      description,
    } = req.body;
    await pool.query(
      "INSERT INTO subscription_plans (name, role, price_per_month, revenue_share_percent, listing_credits, free_months, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [
        name,
        role,
        price_per_month,
        revenue_share_percent,
        listing_credits,
        free_months,
        description,
      ]
    );
    res.status(201).json({ message: "Plan created" });
  }
);

// Admin: Assign subscription after approval
app.post(
  "/api/admin/assign-subscription",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const { userId, planId } = req.body;

    const [plan] = await pool.query(
      "SELECT * FROM subscription_plans WHERE id = ?",
      [planId]
    );
    if (plan.length === 0)
      return res.status(404).json({ error: "Plan not found" });

    // Deactivate old
    await pool.query(
      "UPDATE user_subscriptions SET is_active = FALSE WHERE userId = ?",
      [userId]
    );

    const startDate = new Date().toISOString().slice(0, 10);
    await pool.query(
      'INSERT INTO user_subscriptions (userId, planId, start_date, credits_remaining, payment_status) VALUES (?, ?, ?, ?, "free_trial")',
      [userId, planId, startDate, plan[0].listing_credits]
    );

    res.json({ message: "Subscription assigned with free trial" });
  }
);

// Agent/Hotel Application
app.post("/api/apply", async (req, res) => {
  const { name, email, role } = req.body;
  if (!["agent", "hotel"].includes(role))
    return res.status(400).json({ error: "Invalid role" });

  try {
    await pool.query(
      "INSERT IGNORE INTO applications (name, email, role) VALUES (?, ?, ?)",
      [name, email, role]
    );
    res.json({ message: "Application submitted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get(
  "/api/admin/applications",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const [rows] = await pool.query(
      'SELECT * FROM applications WHERE status = "pending"'
    );
    res.json(rows);
  }
);

app.put(
  "/api/admin/applications/:id/approve",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const { id } = req.params;
    const { planId } = req.body; // Admin chooses which plan to assign

    const [app] = await pool.query(
      'SELECT * FROM applications WHERE id = ? AND status = "pending"',
      [id]
    );
    if (app.length === 0)
      return res.status(400).json({ error: "Invalid application" });

    const password = Math.random().toString(36).slice(-10);
    const hashed = await bcrypt.hash(password, 10);

    const [userResult] = await pool.query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [app[0].name, app[0].email, hashed, app[0].role]
    );

    // Assign subscription
    if (planId) {
      await pool.query(
        'INSERT INTO user_subscriptions (userId, planId, start_date, credits_remaining, payment_status) VALUES (?, ?, CURDATE(), (SELECT listing_credits FROM subscription_plans WHERE id = ?), "free_trial")',
        [userResult.insertId, planId, planId]
      );
    }

    await pool.query(
      'UPDATE applications SET status = "approved" WHERE id = ?',
      [id]
    );

    transporter.sendMail({
      to: app[0].email,
      subject: "Application Approved - Real Estate Portal",
      text: `Welcome! Your account has been approved.\nEmail: ${app[0].email}\nPassword: ${password}\nPlease change your password after login.`,
    });

    res.json({ message: "User created and notified" });
  }
);

app.listen(port, () => {
  console.log(`Real Estate API running on http://localhost:${port}`);
  console.log(`Images served at http://localhost:${port}/uploads/filename.jpg`);
});

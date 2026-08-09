const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

let client;
let bookingCollection;
let dbInitPromise;

function getJwks() {
  return createRemoteJWKSet(new URL(`${clientUrl.replace(/\/+$/, "")}/api/auth/jwks`));
}

function getMongoClient() {
  if (!uri) {
    throw new Error("MONGODB_URI is not set. Please configure the environment variable.");
  }

  if (!client) {
    client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });
  }

  return client;
}

async function ensureDb() {
  if (bookingCollection) {
    return bookingCollection;
  }

  if (dbInitPromise) {
    await dbInitPromise;
    return bookingCollection;
  }

  dbInitPromise = (async () => {
    const mongoClient = getMongoClient();

    let retries = 3;
    while (retries > 0) {
      try {
        await mongoClient.connect();
        const db = mongoClient.db("docAppoint");
        bookingCollection = db.collection("bookings");
        console.log("✓ MongoDB Connected Successfully");
        return bookingCollection;
      } catch (error) {
        retries -= 1;
        if (retries > 0) {
          console.warn(`Connection failed. Retrying... (${retries} attempts left)`);
          await new Promise((resolve) => setTimeout(resolve, 2000));
        } else {
          throw error;
        }
      }
    }
  })();

  await dbInitPromise;
  return bookingCollection;
}

const verifyToken = async (req, res, next) => {
  const authHeader = req?.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const JWKS = getJwks();
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};

app.get("/booking", verifyToken, async (req, res) => {
  try {
    const bookingCollection = await ensureDb();
    const result = await bookingCollection.find().toArray();
    res.send(result);
  } catch (error) {
    console.error("/booking error:", error.message);
    res.status(500).json({ message: "Booking fetch failed", error: error.message });
  }
});

app.get("/booking/my-bookings", verifyToken, async (req, res) => {
  try {
    const bookingCollection = await ensureDb();
    const userEmail = req.user?.email;

    if (!userEmail) {
      return res.status(400).send({
        message: "User email not found in token",
        receivedPayload: req.user,
      });
    }

    const result = await bookingCollection.find({ userEmail }).toArray();
    res.send(result);
  } catch (error) {
    console.error("/booking/my-bookings error:", error.message);
    res.status(500).send({ message: "Server error", error: error.message });
  }
});

app.post("/booking", verifyToken, async (req, res) => {
  try {
    const bookingCollection = await ensureDb();
    const bookingData = req.body;
    const userEmail = req.user?.email;

    const finalBooking = {
      ...bookingData,
      userEmail,
    };

    const result = await bookingCollection.insertOne(finalBooking);
    res.send(result);
  } catch (error) {
    console.error("/booking POST error:", error.message);
    res.status(500).send({ message: "Create failed", error: error.message });
  }
});

app.patch("/booking/:id", verifyToken, async (req, res) => {
  try {
    const bookingCollection = await ensureDb();
    const id = req.params.id;
    const updatedData = req.body;

    const result = await bookingCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );

    res.send(result);
  } catch (error) {
    console.error("/booking PATCH error:", error.message);
    res.status(500).send({ success: false, message: "Update failed", error: error.message });
  }
});

app.delete("/booking/:id", verifyToken, async (req, res) => {
  try {
    const bookingCollection = await ensureDb();
    const id = req.params.id;

    const result = await bookingCollection.deleteOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (error) {
    console.error("/booking DELETE error:", error.message);
    res.status(500).send({ message: "Delete failed", error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send("Server Running");
});

module.exports = app;

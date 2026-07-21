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

if (!uri) {
  console.error("MONGODB_URI is not set. Please configure the environment variable.");
  process.exit(1);
}

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
);


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
    const { payload } = await jwtVerify(token, JWKS);

    req.user = payload;

    next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};


async function run() {
  try {
    // Connect to MongoDB with retries
    let retries = 3;
    while (retries > 0) {
      try {
        await client.connect();
        console.log("✓ MongoDB Connected Successfully");
        break;
      } catch (error) {
        retries--;
        if (retries > 0) {
          console.log(`Connection failed. Retrying... (${retries} attempts left)`);
          await new Promise(resolve => setTimeout(resolve, 2000));
        } else {
          throw error;
        }
      }
    }

    const db = client.db("docAppoint");
    const bookingCollection = db.collection("bookings");

    app.get("/booking", verifyToken, async (req, res) => {
      const result = await bookingCollection.find().toArray();
      res.send(result);
    });

    app.get("/booking/my-bookings", verifyToken, async (req, res) => {
      try {
        const userEmail = req.user?.email;

        console.log("===========================================");
        console.log("JWT Payload:", req.user);
        console.log("User Email:", userEmail);
        console.log("===========================================");

        if (!userEmail) {
          console.error("ERROR: User email not found in token!");
          return res.status(400).send({ 
            message: "User email not found in token",
            receivedPayload: req.user
          });
        }

        console.log(`Searching for bookings with email: ${userEmail}`);
        const result = await bookingCollection
          .find({ userEmail })
          .toArray();

        console.log(`Found ${result.length} bookings`);
        res.send(result);
      } catch (error) {
        console.error("===========================================");
        console.error("ERROR in /booking/my-bookings:");
        console.error("Error Name:", error.name);
        console.error("Error Message:", error.message);
        console.error("Error Stack:", error.stack);
        console.error("===========================================");
        res.status(500).send({ 
          message: "Server error", 
          error: error.message,
          errorName: error.name
        });
      }
    });

    app.post("/booking", verifyToken, async (req, res) => {
      try {
        const bookingData = req.body;

        const userEmail = req.user?.email;

        const finalBooking = {
          ...bookingData,
          userEmail, 
        };

        const result = await bookingCollection.insertOne(finalBooking);

        res.send(result);
      } catch (error) {
        console.log(error);
        res.status(500).send({ message: "Create failed" });
      }
    });

    app.patch("/booking/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;

        const result = await bookingCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        res.send(result);
      } catch (error) {
        console.log(error);
        res.status(500).send({
          success: false,
          message: "Update failed",
        });
      }
    });

    app.delete("/booking/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;

        const result = await bookingCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.send(result);
      } catch (error) {
        console.log(error);
        res.status(500).send({ message: "Delete failed" });
      }
    });

    console.log("MongoDB Connected");
  } catch (error) {
    console.error("✗ MongoDB Connection Error:", error.message);
    console.warn("⚠️  Server will run but MongoDB endpoints will not work until connection is restored.");
    console.warn("Please ensure MongoDB Atlas cluster is RUNNING and network access is configured.");
  }
}

// Don't block server startup on DB connection failure
run().catch(err => console.error("Database initialization error:", err.message));


app.get("/", (req, res) => {
  res.send("Server Running");
});

app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const helmet = require('helmet');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const validator = require('validator');
const Groq = require('groq-sdk');
const { Resend } = require('resend');
const { cleanEnv, str, num, email } = require('envalid');
const { Redis } = require('@upstash/redis');
const { createHash } = require('crypto');
const prom = require('express-prometheus-middleware');
const { setTimeout } = require('timers/promises');

dotenv.config();

// --- Environment Validation ---
const env = cleanEnv(process.env, {
  GROQ_API_KEY: str(),
  RESEND_API_KEY: str(),
  MAIL_FROM: email(),
  PORT: num({ default: 5000 }),
  ALLOWED_ORIGIN: str({ default: 'http://localhost:5173,https://frontend-scribe.onrender.com' }),
  MAX_TRANSCRIPT_CHARS: num({ default: 50000 }),
  MAX_RECIPIENTS: num({ default: 10 }),
  REDIS_URL: str(),
  REDIS_TOKEN: str(),
});

const {
  GROQ_API_KEY,
  RESEND_API_KEY,
  MAIL_FROM: MAIL_FROM_ADDRESS,
  PORT,
  ALLOWED_ORIGIN,
  MAX_TRANSCRIPT_CHARS: MAX_TRANSCRIPT,
  MAX_RECIPIENTS: MAX_RECIPIENTS_NUM,
  REDIS_URL,
  REDIS_TOKEN,
} = env;

// --- Initialize Upstash Redis ---
const redisClient = new Redis({
  url: REDIS_URL,
  token: REDIS_TOKEN,
});

// Test Redis connection
(async () => {
  try {
    const result = await redisClient.ping();
    console.log('✅ Connected to Upstash Redis:', result);
  } catch (err) {
    console.error('❌ Upstash Redis connection failed:', err);
    process.exit(1);
  }
})();

// --- Initialize Express ---
const app = express();

// --- Logging Setup ---
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({ format: winston.format.simple() }));
}

// --- CORS Setup (Updated with fixes) ---
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(o => o.trim());
console.log('Allowed CORS origins:', allowedOrigins);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    const msg = `CORS policy: Origin ${origin} not allowed`;
    logger.warn(msg, { origin, allowedOrigins });
    return callback(new Error(msg));
  },
  methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204, // Some legacy browsers choke on 200
  preflightContinue: false,
};

// Apply CORS middleware before other middleware
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Enable preflight for all routes

// --- Other Middleware ---
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`, { ip: req.ip, origin: req.headers.origin, body: req.body });
  next();
});
app.use(prom({
  metricsPath: '/metrics',
  collectDefaultMetrics: true,
  requestDurationBuckets: [0.1, 0.5, 1, 1.5],
}));

// --- Health Check Endpoint ---
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// --- Rate Limiting ---
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  skip: (req) => req.method === 'OPTIONS',
});
app.use('/api/', apiLimiter);

// --- SDK Clients ---
const groq = new Groq({ apiKey: GROQ_API_KEY });
const resend = new Resend(RESEND_API_KEY);

// --- Simple Email Queue (async, for Upstash REST) ---
const emailQueue = [];
const processEmailQueue = async () => {
  while (true) {
    if (emailQueue.length > 0) {
      const job = emailQueue.shift();
      try {
        const { summaryHtml, summaryText, recipients } = job;
        const cleanHtml = sanitizeHtml(summaryHtml, {
          allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1', 'h2', 'h3']),
          allowedAttributes: { a: ['href', 'name', 'target'], img: ['src', 'alt'] },
        });
        await resend.emails.send({
          from: MAIL_FROM_ADDRESS,
          to: recipients,
          subject: 'Meeting Summary',
          html: cleanHtml,
          text: summaryText || cleanHtml.replace(/<[^>]+>/g, ''),
        });
        console.log(`✅ Email sent to ${recipients.join(', ')}`);
      } catch (err) {
        console.error('❌ Failed to send email:', err);
      }
    }
    await setTimeout(1000);
  }
};
processEmailQueue();

// --- Helpers ---
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const validateRecipients = (arr) => {
  if (!Array.isArray(arr)) return [];
  return arr
    .map((r) => (typeof r === 'string' ? r.trim() : ''))
    .filter((r) => r && validator.isEmail(r));
};

const retry = async (fn, retries = 3, delay = 1000) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === retries - 1) throw err;
      await setTimeout(delay * Math.pow(2, i));
    }
  }
};

// --- Summarize Endpoint ---
app.post('/api/summarize', asyncHandler(async (req, res) => {
  const { transcript, instruction } = req.body ?? {};
  if (!transcript || typeof transcript !== 'string' || !transcript.trim()) {
    return res.status(400).json({ error: 'Transcript required' });
  }

  let trimmedTranscript = transcript.trim();
  if (trimmedTranscript.length > MAX_TRANSCRIPT) {
    trimmedTranscript = trimmedTranscript.slice(0, MAX_TRANSCRIPT);
  }

  const prompt = instruction?.trim() || 'Summarize in bullet points: TL;DR, Decisions, Action Items, Risks';
  const cacheKey = createHash('md5').update(`${prompt}:${trimmedTranscript}`).digest('hex');
  const cachedSummary = await redisClient.get(cacheKey);

  if (cachedSummary) return res.json({ summary: cachedSummary, cached: true });

  const systemMsg = { role: 'system', content: 'You are an expert meeting-note summarizer.' };
  const userMsg = { role: 'user', content: `${prompt}\n\nTranscript:\n${trimmedTranscript}` };

  try {
    const completion = await retry(() => groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [systemMsg, userMsg],
    }));

    const summary = completion?.choices?.[0]?.message?.content ?? null;
    if (!summary) return res.status(502).json({ error: 'No summary generated by model' });

    const safeSummary = sanitizeHtml(summary, { allowedTags: [], allowedAttributes: {} });
    await redisClient.set(cacheKey, safeSummary, { ex: 3600 });
    res.json({ summary: safeSummary });
  } catch (err) {
    logger.error('Groq API error', { message: err.message, stack: err.stack });
    res.status(502).json({ error: `Groq API error: ${err.message}` });
  }
}));

// --- Share via Email ---
app.post('/api/share', asyncHandler(async (req, res) => {
  const { summaryHtml, summaryText, recipients } = req.body ?? {};

  if (!summaryHtml?.trim()) return res.status(400).json({ error: 'summaryHtml is required' });

  const validRecipients = validateRecipients(recipients);
  if (!validRecipients.length) return res.status(400).json({ error: 'Provide at least one valid recipient email' });
  if (validRecipients.length > MAX_RECIPIENTS_NUM) return res.status(400).json({ error: `Maximum ${MAX_RECIPIENTS_NUM} recipients allowed` });

  emailQueue.push({ summaryHtml, summaryText, recipients });
  res.json({ ok: true, queued: true });
}));

// --- Global Error Handler ---
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { message: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// --- Start Server ---
app.listen(PORT, () => {
  logger.info(`Server listening on port ${PORT}`);
});
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
const { createClient } = require('redis');
const { createHash } = require('crypto');
const Queue = require('bull');
const prom = require('express-prometheus-middleware');
const { setTimeout } = require('timers/promises');

dotenv.config();

// --- Environment Validation ---
const env = cleanEnv(process.env, {
  GROQ_API_KEY: str(),
  RESEND_API_KEY: str(),
  MAIL_FROM: email(),
  PORT: num({ default: 5000 }),
  ALLOWED_ORIGIN: str({ default: 'http://localhost:5173' }),
  MAX_TRANSCRIPT_CHARS: num({ default: 50000 }),
  MAX_RECIPIENTS: num({ default: 10 }),
  REDIS_URL: str({ default: 'redis://localhost:6379' }),
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
} = env;

// --- Initialize Redis ---
const redisClient = createClient({ url: REDIS_URL });
redisClient.on('error', (err) => console.error('Redis error:', err));
redisClient.connect().catch(console.error);

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

// --- CORS Setup ---
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(o => o.trim());
console.log('Allowed CORS origins:', allowedOrigins);
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, origin || true);
    } else {
      logger.warn('CORS rejected', { origin, allowedOrigins });
      callback(new Error(`CORS policy: Origin ${origin} not allowed`));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// --- Other Middleware ---
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  console.log('Parsed body:', req.body);
  logger.info(`${req.method} ${req.url}`, { ip: req.ip, origin: req.headers.origin, body: req.body });
  next();
});
app.use(prom({
  metricsPath: '/metrics',
  collectDefaultMetrics: true,
  requestDurationBuckets: [0.1, 0.5, 1, 1.5],
}));

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

// --- Email Queue ---
const emailQueue = new Queue('email-sending', REDIS_URL);
emailQueue.process(async (job) => {
  const { summaryHtml, summaryText, recipients } = job.data;
  const cleanHtml = sanitizeHtml(summaryHtml, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1', 'h2', 'h3']),
    allowedAttributes: { a: ['href', 'name', 'target'], img: ['src', 'alt'] },
  });

  return await resend.emails.send({
    from: MAIL_FROM_ADDRESS,
    to: recipients,
    subject: 'Meeting Summary',
    html: cleanHtml,
    text: summaryText || cleanHtml.replace(/<[^>]+>/g, ''),
  });
});

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

// --- Global Error Handler ---
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// --- Summarize Endpoint ---
app.post(
  '/api/summarize',
  asyncHandler(async (req, res) => {
    console.log('POST /api/summarize, Origin:', req.headers.origin, 'Body:', req.body);
    const { transcript, instruction } = req.body ?? {};

    if (!transcript || typeof transcript !== 'string' || !transcript.trim()) {
      console.log('Rejecting request: Invalid transcript');
      return res.status(400).json({ error: 'Transcript required' });
    }

    let trimmedTranscript = transcript.trim();
    if (trimmedTranscript.length > MAX_TRANSCRIPT) {
      trimmedTranscript = trimmedTranscript.slice(0, MAX_TRANSCRIPT);
    }

    const prompt =
      instruction && typeof instruction === 'string' && instruction.trim()
        ? instruction.trim()
        : 'Summarize in bullet points: TL;DR, Decisions, Action Items, Risks';

    const cacheKey = createHash('md5').update(`${prompt}:${trimmedTranscript}`).digest('hex');
    const cachedSummary = await redisClient.get(cacheKey);

    if (cachedSummary) {
      console.log('Returning cached summary');
      return res.json({ summary: cachedSummary, cached: true });
    }

    const systemMsg = { role: 'system', content: 'You are an expert meeting-note summarizer.' };
    const userMsg = { role: 'user', content: `${prompt}\n\nTranscript:\n${trimmedTranscript}` };

    try {
      const completion = await retry(() =>
        groq.chat.completions.create({
          model: 'llama-3.3-70b-versatile',
          messages: [systemMsg, userMsg],
        })
      );

      const summary = completion?.choices?.[0]?.message?.content ?? null;

      if (!summary) {
        console.log('No summary generated');
        return res.status(502).json({ error: 'No summary generated by model' });
      }

      const safeSummary = sanitizeHtml(summary, { allowedTags: [], allowedAttributes: {} });
      await redisClient.setEx(cacheKey, 3600, safeSummary);
      console.log('Returning new summary');
      res.json({ summary: safeSummary });
    } catch (err) {
      console.error('Groq API error:', err.message, err.stack);
      return res.status(502).json({ error: `Groq API error: ${err.message}` });
    }
  })
);

// --- Share via Email ---
app.post(
  '/api/share',
  asyncHandler(async (req, res) => {
    console.log('POST /api/share, Origin:', req.headers.origin, 'Body:', req.body);
    const { summaryHtml, summaryText, recipients } = req.body ?? {};

    if (!summaryHtml || typeof summaryHtml !== 'string' || !summaryHtml.trim()) {
      return res.status(400).json({ error: 'summaryHtml is required' });
    }

    const validRecipients = validateRecipients(recipients);
    if (!validRecipients.length) {
      return res.status(400).json({ error: 'Provide at least one valid recipient email' });
    }
    if (validRecipients.length > MAX_RECIPIENTS_NUM) {
      return res.status(400).json({ error: `Maximum ${MAX_RECIPIENTS_NUM} recipients allowed` });
    }

    const job = await emailQueue.add({ summaryHtml, summaryText, recipients });
    res.json({ ok: true, jobId: job.id });
  })
);

// --- Start Server ---
app.listen(PORT, () => {
  logger.info(`Backend running on http://localhost:${PORT}`);
});

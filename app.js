require('dotenv').config();
const express = require('express');
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
const { setTimeout } = require('timers/promises');

// --- Environment Validation ---
const env = cleanEnv(process.env, {
  GROQ_API_KEY: str(),
  RESEND_API_KEY: str(),
  MAIL_FROM: email(),
  PORT: num({ default: 5000 }),
  ALLOWED_ORIGIN: str({ default: 'https://frontend-scribe.onrender.com,http://localhost:5173' }),
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

// --- Initialize Services ---
const redisClient = new Redis({ url: REDIS_URL, token: REDIS_TOKEN });
const groq = new Groq({ apiKey: GROQ_API_KEY });
const resend = new Resend(RESEND_API_KEY);
const emailQueue = [];

// --- Express Setup ---
const app = express();

// --- Logging ---
const logger = winston.createLogger({
  level: 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// --- CLOUDFLARE CORS FIX (MUST BE FIRST MIDDLEWARE) ---
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(o => o.trim());
logger.info('Allowed origins configured', { allowedOrigins });

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Bypass Cloudflare header modification
  res.setHeader('Origin-Agent-Cluster', '?0');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');

  // Set dynamic origin if allowed
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.status(204).end();
  }

  next();
});

// --- Security Middleware ---
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for API services
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: '1mb' }));

// --- Request Logging ---
app.use((req, res, next) => {
  logger.info(`Incoming ${req.method} ${req.path}`, {
    origin: req.headers.origin,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  next();
});

// --- Health Check ---
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    cors: {
      allowedOrigins,
      currentOrigin: req.headers.origin,
      allowed: allowedOrigins.includes(req.headers.origin || '')
    }
  });
});

// --- Rate Limiting ---
app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  skip: (req) => req.method === 'OPTIONS',
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', { ip: req.ip });
    res.status(429).json({ error: 'Too many requests' });
  }
}));

// --- Email Queue Processing ---
const processEmailQueue = async () => {
  while (true) {
    if (emailQueue.length > 0) {
      const job = emailQueue.shift();
      try {
        const cleanHtml = sanitizeHtml(job.summaryHtml, {
          allowedTags: ['h1', 'h2', 'h3', 'p', 'ul', 'ol', 'li', 'strong', 'em', 'a'],
          allowedAttributes: {
            a: ['href', 'target']
          }
        });

        await resend.emails.send({
          from: MAIL_FROM_ADDRESS,
          to: job.recipients,
          subject: 'Meeting Summary',
          html: cleanHtml,
          text: job.summaryText || cleanHtml.replace(/<[^>]+>/g, '')
        });
        logger.info('Email sent successfully', { recipients: job.recipients });
      } catch (err) {
        logger.error('Email sending failed', {
          error: err.message,
          stack: err.stack
        });
      }
    }
    await setTimeout(1000);
  }
};
processEmailQueue();

// --- API Endpoints ---
app.post('/api/summarize', async (req, res) => {
  try {
    const { transcript, instruction } = req.body;
    
    if (!transcript || typeof transcript !== 'string') {
      throw new Error('Valid transcript required');
    }

    const trimmedTranscript = transcript.trim().slice(0, MAX_TRANSCRIPT);
    const prompt = instruction?.trim() || 'Summarize in bullet points: TL;DR, Decisions, Action Items, Risks';
    const cacheKey = createHash('md5').update(`${prompt}:${trimmedTranscript}`).digest('hex');

    // Check cache
    const cachedSummary = await redisClient.get(cacheKey);
    if (cachedSummary) {
      return res.json({ summary: cachedSummary, cached: true });
    }

    // Generate new summary
    const completion = await groq.chat.completions.create({
      model: 'llama3-70b-8192',
      messages: [
        { role: 'system', content: 'You are an expert meeting-note summarizer.' },
        { role: 'user', content: `${prompt}\n\nTranscript:\n${trimmedTranscript}` }
      ],
      temperature: 0.7,
    });

    const summary = completion?.choices?.[0]?.message?.content;
    if (!summary) throw new Error('No summary generated');

    const safeSummary = sanitizeHtml(summary, { allowedTags: [], allowedAttributes: {} });
    await redisClient.set(cacheKey, safeSummary, { ex: 3600 });

    res.json({ summary: safeSummary, cached: false });

  } catch (err) {
    logger.error('Summarization error', {
      error: err.message,
      stack: err.stack,
      body: req.body
    });
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/share', async (req, res) => {
  try {
    const { summaryHtml, summaryText, recipients } = req.body;
    
    if (!summaryHtml) throw new Error('summaryHtml is required');
    
    const validRecipients = validateRecipients(recipients);
    if (validRecipients.length === 0) {
      throw new Error('At least one valid recipient required');
    }
    if (validRecipients.length > MAX_RECIPIENTS_NUM) {
      throw new Error(`Maximum ${MAX_RECIPIENTS_NUM} recipients allowed`);
    }

    emailQueue.push({ summaryHtml, summaryText, recipients: validRecipients });
    res.json({ success: true, queued: true });

  } catch (err) {
    logger.error('Share error', { error: err.message });
    res.status(400).json({ error: err.message });
  }
});

// --- Helper Functions ---
function validateRecipients(recipients) {
  if (!Array.isArray(recipients)) return [];
  return recipients
    .map(r => typeof r === 'string' ? r.trim() : '')
    .filter(r => r && validator.isEmail(r));
}

// --- Server Start ---
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`, {
    nodeEnv: process.env.NODE_ENV,
    allowedOrigins
  });
});

// --- Error Handling ---
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled rejection', { error: err.message });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message });
  process.exit(1);
});
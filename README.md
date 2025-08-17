# ScribeDigest Backend
1. Install Node.js 18+ from nodejs.org.
2. Install Docker Desktop from docker.com.
3. Run Redis: `docker run -d -p 6379:6379 --name redis redis`.
4. Install dependencies: `npm install`.
5. Set up .env with GROQ_API_KEY, RESEND_API_KEY, and other variables.
6. Run: `node app.js`.

# ScribeDigest Frontend
1. Install Node.js 18+ from nodejs.org.
2. Install dependencies: `npm install`.
3. Set up .env with VITE_API_BASE=http://localhost:5000.
4. Run: `npm run dev`.
5. Open http://localhost:5173 in a browser.
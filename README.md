# vibesync-backend
"Node.js &amp; Express.js backend for VibeSync, featuring a hybrid AI recommendation engine, MongoDB Atlas persistence, and secure OTP-based authentication via Nodemailer."


VibeSync: AI-Powered Music Synchronization
VibeSync is a full-stack music streaming platform that leverages a custom-built hybrid recommendation engine to deliver a personalized listening experience. By analyzing user favorites, recently played history (capped at 25 songs), and custom playlists, the system dynamically synchronizes recommendations with the user’s evolving taste in real-time.

Core Features:
AI Recommendation Engine: A weighted scoring algorithm that analyzes Genre and Artist affinity across three data sources to provide high-accuracy suggestions.

Secure OTP Authentication: A passwordless login system using NodeMailer and custom HTML templates for a secure, branded entry experience.

Smart History Management: A server-side capped array (FILO) that persists the user's last 25 plays, ensuring a consistent vibe profile across sessions.

Dynamic Playlist Control: Full CRUD operations for custom playlists, allowing users to curate their own collections with real-time database persistence.

Pro UI/UX: A modern interface featuring glassmorphism, Lucide-integrated iconography, and smooth micro-animations for favorites and playback.

🛠️ Technical Stack
Frontend: HTML5, CSS3 (Custom Glassmorphism), JavaScript (ES6+), Bootstrap 5, Lucide Icons.

Backend: Node.js, Express.js.

Database: MongoDB Atlas with Mongoose ODM.

Automation: Node-Cron for daily account maintenance and inactive user notifications.

Deployment: Backend hosted on Render; Frontend hosted on Vercel.

📂 Project Structure
Plaintext
├── backend/
│   ├── server.js           # Express server & API routes
│   ├── recommender.js      # Hybrid AI recommendation logic
│   ├── otp-email.html      # Responsive email template
│   └── .env                # Environment variables (Protected)
└── frontend/
    ├── home.html           # Main player interface
    ├── scripts/
    │   └── script.js       # Global state & UI synchronization
    └── styles/
        └── styles.css      # Custom design system
⚙️ Setup & Installation
Clone the Repository:

Bash
git clone https://github.com/yourusername/vibesync.git
Configure Environment Variables:
Create a .env file in the root and add your MongoDB URI and Gmail App Password.

Install Dependencies:

Bash
npm install
Run Locally:

Bash
npm start

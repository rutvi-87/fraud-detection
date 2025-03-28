require('dotenv').config();
const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const whois = require('whois-json');
const { getDomain } = require('tldjs');

const app = express();
const PORT = process.env.PORT || 10000;

// CORS Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Root Route
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// WHOIS Lookup Function
async function checkWhoisData(domain) {
    try {
        const cleanDomain = domain.replace(/^www\./, '');
        const result = await whois(cleanDomain);

        const wellKnownDomains = ['facebook.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com'];
        if (wellKnownDomains.includes(cleanDomain)) {
            return {
                creationDate: result.creationDate,
                expirationDate: result.expirationDate,
                privacyProtection: false,
                ageInDays: 365 * 15, // Assume minimum 15 years for well-known domains
                isWellKnown: true
            };
        }

        return {
            creationDate: result.creationDate,
            expirationDate: result.expirationDate,
            privacyProtection: !result.registrant,
            ageInDays: result.creationDate ? 
                Math.floor((Date.now() - new Date(result.creationDate)) / (1000 * 60 * 60 * 24)) : null
        };
    } catch (error) {
        console.error('WHOIS lookup failed:', error);
        return null;
    }
}

// Domain Check API
app.post('/check-domain', async (req, res) => {
    const { domain } = req.body;

    if (!domain) {
        return res.status(400).json({ error: '⚠️ Domain is required.' });
    }

    try {
        const cleanDomain = domain.replace(/^www\./, '');
        
        const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${cleanDomain}`, {
            headers: { 
                'x-apikey': process.env.VIRUS_TOTAL_API_KEY,
                'Content-Type': 'application/json'
            },
            timeout: 15000
        });

        const data = response.data.data;
        const stats = data.attributes.last_analysis_stats || {};
        const trustScore = calculateTrustScore(data);
        
        const domainInfo = {
            domain: cleanDomain,
            trustScore,
            stats,
            lastAnalysisDate: data.attributes.last_analysis_date,
            registrar: data.attributes.registrar || "Unknown",
            creationDate: data.attributes.creation_date
        };

        res.json({
            trustScore: domainInfo.trustScore,
            stats: domainInfo.stats,
            reportLink: `https://www.virustotal.com/gui/domain/${cleanDomain}/detection`
        });

    } catch (error) {
        console.error("❌ Error details:", error.response?.data || error.message);
        
        res.status(500).json({ 
            error: 'Failed to fetch domain details',
            details: error.response?.data?.error?.message || 'Unknown error occurred'
        });
    }
});

// Helper function to calculate trust score
function calculateTrustScore(data) {
    const stats = data.attributes.last_analysis_stats;
    if (!stats) return 30; // Base score for unknown domains
    
    let score = 50; // Start with a neutral score

    const weights = {
        malicious: -40,
        suspicious: -20,
        harmless: 15,
        undetected: 5
    };

    Object.entries(stats).forEach(([key, value]) => {
        score += (value / Object.values(stats).reduce((sum, val) => sum + val, 0)) * (weights[key] || 0);
    });

    return Math.max(0, Math.min(100, Math.round(score)));
}

// Ensure PORT is set
if (!PORT) {
    console.error("❌ ERROR: PORT is not defined in the environment variables.");
    process.exit(1);
}

// Start the server
app.listen(PORT, () => {
    console.log(`✅ Server running on PORT: ${PORT}`);
});

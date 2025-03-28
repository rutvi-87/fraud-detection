require('dotenv').config();
const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const whois = require('whois-json');
const { getDomain } = require('tldjs');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

const checkedDomains = {};

// Add this utility function
// Update the checkWhoisData function to handle well-known domains
async function checkWhoisData(domain) {
    try {
        // Clean domain name (remove www. if present)
        const cleanDomain = domain.replace(/^www\./, '');
        
        const result = await whois(cleanDomain);
        
        // Handle well-known domains differently
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

// Update the check-ai-fraud endpoint's WHOIS analysis section
app.post('/check-ai-fraud', async (req, res) => {
    const { domain, trustScore, stats } = req.body;
    
    try {
        let score = parseFloat(trustScore) || 50;
        let riskFactors = [];
        
        // Clean domain name
        const cleanDomain = domain.replace(/^www\./, '');

        // WHOIS data analysis
        const whoisData = await checkWhoisData(cleanDomain);
        if (whoisData) {
            if (whoisData.isWellKnown) {
                score = Math.max(score, 90); // Ensure high score for well-known domains
            } else if (whoisData.ageInDays < 30) {
                score *= 0.7;
                riskFactors.push("Domain is less than 30 days old");
            } else if (whoisData.ageInDays < 90) {
                score *= 0.85;
                riskFactors.push("Domain is less than 90 days old");
            }
        }

        // Malicious activity impact
        if (stats.malicious > 0) {
            score *= 0.5;
            riskFactors.push(`Detected ${stats.malicious} malicious activities`);
        }
        if (stats.suspicious > 0) {
            score *= 0.7;
            riskFactors.push(`Detected ${stats.suspicious} suspicious activities`);
        }

        const finalScore = Math.max(0, Math.min(100, Math.round(score)));

        res.json({
            score: finalScore,
            warnings: riskFactors.join('. '),
            riskLevel: getRiskLevel(finalScore)
        });

    } catch (error) {
        console.error("❌ Error:", error.message);
        res.status(500).json({ error: 'Failed to assess fraud risk' });
    }
});

// Helper function for risk level determination
function getRiskLevel(score) {
    if (score >= 85) return "Very Safe";
    if (score >= 70) return "Safe";
    if (score >= 50) return "Medium Risk";
    if (score >= 30) return "High Risk";
    return "Very High Risk";
}

// Add this near the top with other functions
const calculateTrustScore = (data) => {
    const stats = data.attributes.last_analysis_stats;
    if (!stats) return 30; // Base score for unknown domains
    
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (total === 0) return 30;
    
    let score = 50; // Start with neutral score
    
    // Weighted impact calculation
    const weights = {
        malicious: -40,    // Heavy negative impact
        suspicious: -20,    // Moderate negative impact
        harmless: 15,      // Positive impact
        undetected: 5      // Slight positive impact
    };

    // Calculate weighted score
    Object.entries(stats).forEach(([key, value]) => {
        score += (value / total) * weights[key];
    });

    // Domain reputation checks
    const cleanDomain = data.id.replace(/^www\./, '');
    const wellKnownDomains = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com'];
    
    if (wellKnownDomains.includes(cleanDomain)) {
        return 95; // Trusted domains override
    }

    // Age-based adjustments
    if (data.attributes.creation_date) {
        const ageInDays = (Date.now() - data.attributes.creation_date * 1000) / (1000 * 60 * 60 * 24);
        if (ageInDays < 30) score *= 0.4;      // Severe penalty for very new domains
        else if (ageInDays < 90) score *= 0.6;  // Major penalty for newer domains
        else if (ageInDays < 180) score *= 0.8; // Moderate penalty for recent domains
    }

    // Additional risk factors
    const riskPatterns = /(crypto|token|wallet|invest|bank|secure|login|verify|account|payment)/i;
    if (riskPatterns.test(cleanDomain)) {
        score *= 0.6; // Significant reduction for suspicious keywords
    }

    return Math.max(0, Math.min(100, Math.round(score)));
};

// Update getRiskLevel for more accurate risk assessment
function getRiskLevel(score) {
    if (score >= 90) return "Very Safe";
    if (score >= 75) return "Safe";
    if (score >= 60) return "Medium Risk";
    if (score >= 40) return "High Risk";
    return "Very High Risk";
}

// Update the check-domain endpoint response
app.post('/check-domain', async (req, res) => {
    const { domain } = req.body;

    if (!domain) {
        return res.status(400).json({ error: '⚠️ Domain is required.' });
    }

    try {
        // Clean domain for API request
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
        
        // Calculate VirusTotal's reputation score (0-100 scale)
        const vtReputationScore = Math.max(0, Math.min(100, 
            ((stats.harmless || 0) / (Object.values(stats).reduce((sum, val) => sum + val, 0))) * 100
        ));
        
        const domainInfo = {
            domain: cleanDomain,
            trustScore,
            vtScore: Math.round(vtReputationScore),
            stats: {
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                harmless: stats.harmless || 0,
                undetected: stats.undetected || 0
            },
            lastAnalysisDate: data.attributes.last_analysis_date,
            registrar: data.attributes.registrar || "Unknown",
            creationDate: data.attributes.creation_date
        };

        checkedDomains[cleanDomain] = domainInfo;
        
        res.json({
            trustScore: domainInfo.trustScore,
            virusTotalScore: domainInfo.vtScore,
            stats: domainInfo.stats,
            reportLink: `https://www.virustotal.com/gui/domain/${cleanDomain}/detection`
        });

    } catch (error) {
        console.error("❌ Error details:", error.response?.data || error.message);
        
        if (error.response?.status === 401) {
            return res.status(401).json({ error: 'Invalid API key. Please check your configuration.' });
        }
        if (error.response?.status === 403) {
            return res.status(403).json({ error: 'API quota exceeded. Please try again later.' });
        }
        if (error.code === 'ECONNABORTED') {
            return res.status(504).json({ error: 'Request timeout. Please try again.' });
        }
        
        res.status(500).json({ 
            error: 'Failed to fetch domain details',
            details: error.response?.data?.error?.message || 'Unknown error occurred'
        });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});

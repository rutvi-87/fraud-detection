# Deploying on Render

This guide will help you deploy your Investment Fraud Detection website on Render.

## Prerequisites

1. A Render account (create one at https://render.com if you don't have it)
2. Your project code in a GitHub repository
3. Your VirusTotal API key

## Step-by-Step Deployment Guide

### 1. Prepare Your Project

1. Ensure your package.json has:
   - All dependencies listed
   - A start script: `"start": "node server.js"`
   - Node.js version specified: 
     ```json
     "engines": {
       "node": "14.x"
     }
     ```

2. Update your server.js to use environment port:
   ```javascript
   const port = process.env.PORT || 3000;
   ```

### 2. Deploy to Render

1. Sign up or log in to Render (https://render.com)

2. From the Render dashboard:
   - Click "New +"
   - Select "Web Service"

3. Connect your GitHub repository:
   - Choose the repository containing your fraud detection system
   - Select the branch you want to deploy

4. Configure your web service:
   - Name: Choose a name for your service
   - Environment: Node
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Select the Free plan (or paid if needed)

5. Set environment variables:
   - Click on "Environment"
   - Add your VirusTotal API key:
     - Key: `VIRUS_TOTAL_API_KEY`
     - Value: Your API key

6. Click "Create Web Service"

### 3. Monitor Deployment

1. Render will automatically:
   - Clone your repository
   - Install dependencies
   - Start your application

2. Monitor the deployment logs for any errors

3. Once deployed, you'll get a URL like: `https://your-app-name.onrender.com`

### 4. Testing Your Deployment

1. Test your endpoints using the complete URL:
   - Example: `https://your-app-name.onrender.com/analyze`

2. Monitor your application:
   - Check logs in the Render dashboard
   - Monitor performance metrics

## Important Notes

- Free tier limitations:
  - Limited bandwidth and build minutes
  - May have cold starts
- Keep your API keys secure
- Enable auto-deploy for automatic updates when you push to GitHub

## Troubleshooting

1. Common issues:
   - Build failures: Check build logs
   - Application crashes: Review application logs
   - Environment variables not working: Verify in dashboard

2. If you encounter issues:
   - Check Render's status page
   - Review the deployment logs
   - Consult Render's documentation

## Support

- Render Documentation: https://render.com/docs
- Render Status: https://status.render.com
- Render Support: https://render.com/support
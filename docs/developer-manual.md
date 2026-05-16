# Developer Manual

## Overview
SentinalScope is a cybersecurity exposure monitoring dashboard project that hopes to solve the issue of publicly exposed internet connected devices and services. This project uses the Shodan API to retrieve publicly available cybersecurity information associated with a domain name or IP address.

The application uses:
- Frontend: HTML/CSS, React, Chart.js for data visualization, Leaflet.js for interactive maps
- Backend: JavaScript, Node.js, Express.js, Supabase Database, Vercel for deployment
Supabase Database
- Shodan API integration

# Technologies Used:

## Frontend
- React
- HTML/CSS
- JavaScript
- Chart.js = data visualization
- Leaflet.js = geolocation

## Backend
- Node.js
- Express.js

## Database
- Supabase

## Deployment
- Vercel

## API
- Shodan API

# Installation Guide

## Clone Repository

git clone https://github.com/iadenuga/sentinelscope.git
cd sentinelscope

## Install Frontend
npm install

# Environment Variables
Create a .env file in the root directory of the project

env
SHODAN_API_KEY = adfkl;asda
SUPABASE_URL = djafl;
SUPABASE_key =  ajd;fkla
PORT = 3000

# Run the Application

## Run Server

npm start

Run the application using:
node index.js

Application runs locally on port 3000

## Start development server

npm run dev

runs application using Nodemon in development mode

# Run test for software
 - Frontend testing
 - API endpoint testing
 - UI functioinality testing

# API endpoints

## GET /api/scan/:target

Retrieves publicly exposed cybersecurity information that is associated with a domain or IP address through Shodan API

## POST /api/history

This saves scan results after they are deemed successful. These then later appear on the users home page history table

## GET /api/history

Retrieves recent scan history from Supabase database. Allows the home page to display most recent searches and exposure history.

# Known Bugs

- Slow repeated searches due to Shodan API limitations
- Some domains do not provide full geolocation data
- Interactive map markers may fail to display and refresh properly
- Simplified execution for exposure risk calculations

# Future Roadmap
- Improve user functionality such as user authentication, user dashboards, email alerts
- Optimize project for mobile UI/UX desing
- Real-time monitoring
- Better exposure risk calculations
- Integrate other API's that are cyber related

# Deployment in Vercel
1. Push project to Github
2. Connect repository to Vercel
3. Configure env variables
4. Deploy the app

Needs Shodan API Key, Supabase URL, and Supabase Key

# Important message
The use of SentinelScope is for educational cybersecurity awareness purposes only. Users should only scan system they either own or have authorization to test.

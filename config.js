// Configuration - CHANGE THIS to your GitHub Pages backend URL
const API_URL = 'https://mohamedsillahkanu.github.io/mdm-backend-api/api';

// Don't change anything below this line
let devices = [];
let authToken = localStorage.getItem('mdm_token') || 'demo-token-123';

// verify-redflagged.js
// Run this script to verify RedFlagged backend is working
// Usage: node verify-redflagged.js

const https = require('https');

const BACKEND_URL = 'https://urown-backend.onrender.com';
const FRONTEND_ORIGIN = 'https://urown-delta.vercel.app';

console.log('🔍 Verifying RedFlagged Backend Setup...\n');

// Helper function to make requests
function makeRequest(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = `${BACKEND_URL}${path}`;
    const requestOptions = {
      method: options.method || 'GET',
      headers: {
        'Origin': FRONTEND_ORIGIN,
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    console.log(`Testing: ${requestOptions.method} ${url}`);

    const req = https.request(url, requestOptions, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: jsonData
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: data
          });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (options.body) {
      req.write(JSON.stringify(options.body));
    }

    req.end();
  });
}

// Test functions
async function testHealthCheck() {
  console.log('\n📍 Test 1: Health Check');
  try {
    const response = await makeRequest('/api/health');
    
    if (response.status === 200) {
      console.log('✅ Backend is running');
      console.log('   Response:', response.data);
      return true;
    } else {
      console.log('❌ Health check failed:', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ Backend not reachable:', error.message);
    return false;
  }
}

async function testCORS() {
  console.log('\n📍 Test 2: CORS Headers');
  try {
    const response = await makeRequest('/api/redflagged');
    
    const corsHeader = response.headers['access-control-allow-origin'];
    const credsHeader = response.headers['access-control-allow-credentials'];
    
    if (corsHeader === FRONTEND_ORIGIN || corsHeader === '*') {
      console.log('✅ CORS header present:', corsHeader);
    } else {
      console.log('❌ CORS header missing or incorrect');
      console.log('   Expected:', FRONTEND_ORIGIN);
      console.log('   Got:', corsHeader);
      return false;
    }
    
    if (credsHeader === 'true') {
      console.log('✅ Credentials allowed');
    } else {
      console.log('⚠️  Credentials not allowed (may cause issues)');
    }
    
    return true;
  } catch (error) {
    console.log('❌ CORS test failed:', error.message);
    return false;
  }
}

async function testRedFlaggedBrowse() {
  console.log('\n📍 Test 3: RedFlagged Browse Endpoint');
  try {
    const response = await makeRequest('/api/redflagged?limit=5&offset=0');
    
    if (response.status === 200) {
      console.log('✅ Browse endpoint working');
      console.log('   Posts returned:', response.data.posts?.length || 0);
      console.log('   Total:', response.data.total || 0);
      
      if (response.data.posts) {
        return true;
      } else {
        console.log('❌ Response missing "posts" field');
        return false;
      }
    } else {
      console.log('❌ Browse endpoint failed:', response.status);
      console.log('   Response:', response.data);
      return false;
    }
  } catch (error) {
    console.log('❌ Browse test failed:', error.message);
    return false;
  }
}

async function testTrendingCompanies() {
  console.log('\n📍 Test 4: Trending Companies Endpoint');
  try {
    const response = await makeRequest('/api/redflagged/trending/companies?limit=5');
    
    if (response.status === 200) {
      console.log('✅ Trending companies endpoint working');
      console.log('   Companies returned:', response.data.companies?.length || 0);
      return true;
    } else {
      console.log('❌ Trending companies failed:', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ Trending companies test failed:', error.message);
    return false;
  }
}

async function testCreatePost() {
  console.log('\n📍 Test 5: Create Post Endpoint');
  try {
    const testPost = {
      company_name: 'Test Company',
      position: 'Test Position',
      experience_type: 'Great Experience',
      story: 'This is a test post to verify the RedFlagged feature is working correctly. This needs to be at least 100 characters long so it passes validation.',
      rating_fairness: 5,
      rating_pay: 5,
      rating_culture: 5,
      rating_management: 5,
      anonymous_username: 'TestUser123',
      is_anonymous: true,
      terms_agreed: true
    };
    
    const response = await makeRequest('/api/redflagged', {
      method: 'POST',
      body: testPost
    });
    
    if (response.status === 201) {
      console.log('✅ Create post endpoint working');
      console.log('   Post ID:', response.data.post?.id);
      return response.data.post?.id;
    } else {
      console.log('❌ Create post failed:', response.status);
      console.log('   Error:', response.data);
      return null;
    }
  } catch (error) {
    console.log('❌ Create post test failed:', error.message);
    return null;
  }
}

async function testGetPost(postId) {
  if (!postId) {
    console.log('\n⏭️  Test 6: Skipped (no post ID)');
    return false;
  }
  
  console.log('\n📍 Test 6: Get Single Post');
  try {
    const response = await makeRequest(`/api/redflagged/${postId}`);
    
    if (response.status === 200) {
      console.log('✅ Get post endpoint working');
      console.log('   Post title:', response.data.post?.company_name);
      return true;
    } else {
      console.log('❌ Get post failed:', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ Get post test failed:', error.message);
    return false;
  }
}

// Run all tests
async function runAllTests() {
  console.log('========================================');
  console.log('🚩 RedFlagged Backend Verification');
  console.log('========================================');
  console.log(`Backend: ${BACKEND_URL}`);
  console.log(`Frontend: ${FRONTEND_ORIGIN}`);
  
  const results = {
    healthCheck: false,
    cors: false,
    browse: false,
    trending: false,
    create: false,
    getPost: false
  };
  
  // Run tests
  results.healthCheck = await testHealthCheck();
  results.cors = await testCORS();
  results.browse = await testRedFlaggedBrowse();
  results.trending = await testTrendingCompanies();
  
  const postId = await testCreatePost();
  results.create = postId !== null;
  results.getPost = await testGetPost(postId);
  
  // Summary
  console.log('\n========================================');
  console.log('📊 Test Summary');
  console.log('========================================');
  
  const tests = [
    { name: 'Health Check', result: results.healthCheck },
    { name: 'CORS Configuration', result: results.cors },
    { name: 'Browse Posts', result: results.browse },
    { name: 'Trending Companies', result: results.trending },
    { name: 'Create Post', result: results.create },
    { name: 'Get Single Post', result: results.getPost }
  ];
  
  tests.forEach(test => {
    const icon = test.result ? '✅' : '❌';
    console.log(`${icon} ${test.name}`);
  });
  
  const passedTests = tests.filter(t => t.result).length;
  const totalTests = tests.length;
  
  console.log('\n========================================');
  console.log(`Results: ${passedTests}/${totalTests} tests passed`);
  console.log('========================================\n');
  
  if (passedTests === totalTests) {
    console.log('🎉 All tests passed! RedFlagged is ready to use.');
    console.log('\nNext steps:');
    console.log('1. Go to https://urown-delta.vercel.app/redflagged');
    console.log('2. You should see the browse page (may be empty)');
    console.log('3. Click "Share Your Story" to create a post');
  } else if (passedTests === 0) {
    console.log('❌ All tests failed. Backend may not be running or routes not added.');
    console.log('\nTroubleshooting:');
    console.log('1. Check Render dashboard - is service running?');
    console.log('2. Check Render logs for errors');
    console.log('3. Verify RedFlagged routes are in server.js');
    console.log('4. Verify routes are BEFORE React catch-all');
  } else {
    console.log('⚠️  Some tests failed. Check the results above.');
    console.log('\nIf CORS failed:');
    console.log('1. Update CORS config in server.js');
    console.log('2. Ensure origin includes:', FRONTEND_ORIGIN);
    console.log('3. Redeploy to Render');
  }
}

// Run the tests
runAllTests().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

// Export for use in other scripts
module.exports = { makeRequest, runAllTests };
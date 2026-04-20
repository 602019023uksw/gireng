#!/bin/bash
# Test GLM-5 API with curl

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

API_KEY="${ANTHROPIC_API_KEY:-${LLM_API_KEY}}"
API_BASE="${ANTHROPIC_BASE_URL:-${LLM_BASE_URL}}"
MODEL="${ANTHROPIC_MODEL:-${LLM_MODEL_NAME:-glm-5}}"

echo "Testing GLM-5 API..."
echo "Model: $MODEL"
echo "API Base: ${API_BASE:-default}"
echo "API Key: ${API_KEY:0:8}...${API_KEY: -4}"
echo "----------------------------------------"

if [ -z "$API_KEY" ]; then
    echo "❌ ERROR: No API key found!"
    echo "   Set ANTHROPIC_API_KEY in .env"
    exit 1
fi

# Build the API endpoint
if [ -n "$API_BASE" ]; then
    ENDPOINT="$API_BASE/v1/chat/completions"
else
    ENDPOINT="https://open.bigmodel.cn/api/paas/v4/chat/completions"
fi

echo "Endpoint: $ENDPOINT"
echo "Sending test request..."

# Make the API call
response=$(curl -s -w "\n%{http_code}" "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{
        \"model\": \"$MODEL\",
        \"messages\": [
            {\"role\": \"user\", \"content\": \"Say 'API test successful' in exactly those words.\"}
        ],
        \"max_tokens\": 50
    }" 2>/dev/null)

# Split response and status code
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

echo ""
echo "HTTP Status: $http_code"
echo "Response:"
echo "$body" | jq '.' 2>/dev/null || echo "$body"

if [ "$http_code" = "200" ]; then
    content=$(echo "$body" | jq -r '.choices[0].message.content' 2>/dev/null)
    echo ""
    echo "✅ API Call Successful!"
    echo "Response: $content"
    exit 0
else
    echo ""
    echo "❌ API Call Failed!"
    exit 1
fi

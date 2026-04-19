# GLM-5 Deep Reasoning Enhancements

## Summary
Enhanced gireng's LLM integration to use GLM-5's advanced deep reasoning capabilities, function calling, and multi-layered memory system from the Z.AI API.

## Changes Made

### 1. Configuration Updates
- **Model**: `glm-5` (latest model with enhanced reasoning)
- **Endpoint**: `https://api.z.ai/api/coding/paas/v4` (Coding Plan endpoint)
- **Features Enabled**:
  - Deep thinking (`thinking: {type: "enabled"}`)
  - Preserved thinking (`clear_thinking: false`)
  - Temperature: 1.0 (GLM-5.1 default)
  - Top-P: 0.95 (GLM-5.1 default)
  - **Function Calling**: Dynamic tool invocation
  - **Memory Mechanism**: Multi-layered context retention

### 2. Backend Code Changes

#### `backend/src/ghidra_agent/llm.py`
- Updated `_single_llm_call()` to support GLM-5.1 deep reasoning parameters
- Added `tools` and `tool_executor` parameters for function calling
- Added `max_tool_iterations` to control multi-step tool usage
- Returns dict with `content`, `reasoning_content`, `tool_calls`, and `tool_results`
- Added `create_tool_executor()` and `get_function_calling_tools()` helper functions

#### `backend/src/ghidra_agent/glm_function_tools.py` (NEW)
- Tool registry for GLM function calling
- Converts LangChain tools to GLM function format
- Registers radare2 analysis tools:
  - `r2_analyze_binary`: Get binary structure
  - `r2_list_functions`: List all functions
  - `r2_build_call_graph`: Build call graph
  - `r2_decompile_function`: Decompile specific function
  - `r2_disassemble_at`: Disassemble at address
  - `r2_find_strings`: Find all strings
  - `r2_find_xrefs`: Find cross-references
  - `r2_search_bytes`: Search byte patterns
- Utility tools:
  - `search_functions`: Search previously analyzed functions
  - `get_decompilation`: Get cached decompilation

#### `backend/src/ghidra_agent/memory.py` (NEW)
- **Project Memory**: Analysis rules, patterns, and conventions
- **Episodic Memory**: Records of previous analyses and outcomes
- **Semantic Memory**: Vector-based similarity search for related analyses
- `MemoryManager`: Unified interface for all memory layers
- Automatic recording of analysis results in episodic memory
- Context retrieval for LLM prompts

#### `backend/src/ghidra_agent/api/memory_routes.py` (NEW)
- `GET /api/memory/project/rules` - Get all project-level analysis rules
- `POST /api/memory/project/rules` - Add or update analysis rules
- `GET /api/memory/episodic/recent` - Get recent analysis episodes
- `GET /api/memory/episodic/hash/{hash}` - Get analysis by binary hash
- `GET /api/memory/episodic/similar` - Find similar analyses
- `GET /api/memory/statistics` - Get memory statistics
- `GET /api/memory/context` - Get formatted memory context
- `POST /api/memory/record` - Record analysis in memory

#### `backend/src/ghidra_agent/api/main.py`
- Updated query handling to extract and return reasoning content
- Added `/query_with_tools` endpoint for function calling queries
- Enhanced response includes both answer and reasoning
- Stores reasoning in QA history for context preservation
- Integrated memory context into query flow

#### `backend/src/ghidra_agent/graph.py`
- Updated synthesis to handle reasoning content
- Stores synthesis reasoning in state for reference
- **Automatic memory recording** after analysis completion
- Records verdict, capabilities, techniques, and summary

### 3. Environment Variables
Updated `.env` and `.env.template` with:
- GLM-5.1 model configuration
- Coding Plan endpoint
- Documentation of deep reasoning, function calling, and memory features
- `MEMORY_DIR`: Path for memory storage (default: `/data/memory`)

## Features Enabled

### Deep Thinking
- Model performs chain-of-thought reasoning before answering
- Improves accuracy for complex binary analysis tasks
- Automatically determines depth of reasoning needed

### Preserved Thinking
- Reasoning content is retained across conversation turns
- Maintains context continuity in multi-turn sessions
- Increases cache hit rates, saving tokens

### Function Calling
- LLM can dynamically invoke radare2 analysis tools
- Multi-step reasoning with tool results fed back to model
- Automatic tool selection based on user query
- Safe parameter injection (session_id, program_hash, binary_path)

### Memory Mechanism
- **Project Memory**: Persistent analysis rules and patterns
  - Default rules for malware analysis priorities
  - Common evasion patterns to look for
  - Suspicious import combinations
  - Function naming conventions
  - Report structure guidelines
- **Episodic Memory**: Records of previous analyses
  - Automatic recording after each analysis
  - Stores verdict, capabilities, techniques, IOC count
  - Searchable by verdict, capability, or technique
  - Finding similar previous analyses
- **Semantic Memory**: Pattern-based similarity search
  - Keyword matching for finding related analyses
  - Fallback to embeddings when available

### Enhanced Token Handling
- Max context: 200K tokens
- Max output: 128K tokens
- Separate tracking of reasoning tokens vs content tokens

## Testing Results

✅ **API Connection**: Working
- Endpoint: `https://api.z.ai/api/coding/paas/v4/chat/completions`
- Model: `glm-5`
- Authentication: Successful

✅ **Deep Thinking**: Verified
- Returns reasoning_content with detailed analysis
- Returns final answer content
- Properly tracks reasoning vs content tokens

✅ **Function Calling**: Implemented
- Tools registered in GLM format
- Executor handles tool calls and results
- Multi-step iteration supported

✅ **Memory Mechanism**: Implemented
- Project rules initialized with defaults
- Episodic recording after analysis
- Search by similarity available

## Benefits for Binary Analysis

1. **Better Complex Reasoning**: Deep thinking improves analysis of complex malware
2. **Step-by-Step Analysis**: Model shows reasoning process for transparency
3. **Multi-Turn Context**: Preserved thinking maintains analysis coherence across sessions
4. **Larger Context**: 200K context allows analyzing entire binaries at once
5. **Dynamic Tool Use**: LLM can invoke radare2 tools on-demand during analysis
6. **Interactive Exploration**: Users can ask questions that trigger specific analysis
7. **Knowledge Accumulation**: System learns from each analysis
8. **Pattern Recognition**: Identifies similar malware families and techniques
9. **Consistent Analysis**: Project rules ensure standardized approaches

## Usage

### Regular Query (with reasoning)
```bash
curl -X POST /query \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"session_id": "...", "query": "What functions handle network connections?"}'
```

### Query with Function Calling
```bash
curl -X POST /query_with_tools \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"session_id": "...", "query": "Decompile the main function and find all string references"}'
```

### Memory Management
```bash
# Get memory statistics
curl -X GET /api/memory/statistics

# Get similar analyses
curl -X GET "/api/memory/episodic/similar?verdict=malicious&capability=C2+Communication"

# Add project rule
curl -X POST "/api/memory/project/rules?category=Custom+Rule&rule=Specific+analysis+guideline"
```

The system now:
- Enables deep thinking for all LLM calls
- Returns reasoning content in API responses
- Supports function calling for dynamic analysis
- Records analyses in episodic memory
- Provides project-level analysis rules
- Finds similar previous analyses
- Preserves reasoning across conversation turns
- Uses optimal sampling parameters for coding tasks

## Memory Storage

Memory is stored in `/data/memory/` by default:
- `project_memory.md` - Analysis rules and patterns
- `episodic_memory.jsonl` - Previous analysis records
- `semantic_index.json` - Semantic search index

## Next Steps

Build and start the services:
```bash
docker-compose build && docker-compose up -d
```

The system will now use GLM-5.1 with enhanced deep reasoning, function calling, and memory for all binary analysis tasks.

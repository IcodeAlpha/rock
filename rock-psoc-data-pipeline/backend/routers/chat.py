"""
AI Chat Router
POST /api/chat - Send message to AI security analyst
GET /api/chat/history - Get conversation history
POST /api/chat/briefing - Generate automated security briefing
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
import google.generativeai as genai
import os

from backend.services.supabase_service import (
    get_all_threats,
    get_dashboard_stats
)

router = APIRouter()

# Initialize Gemini client
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

if not GEMINI_API_KEY:
    print("⚠️  WARNING: GEMINI_API_KEY not set. AI chat will not work.")
    print("   Add GEMINI_API_KEY=your_key_here to your .env file")
    client = None
else:
    genai.configure(api_key=GEMINI_API_KEY)
    client = genai.GenerativeModel("gemini-2.5-flash")
    print("✅ Using Gemini for AI chat")

# Request/Response schemas
class ChatMessage(BaseModel):
    role: str = Field(..., description="'user' or 'assistant'")
    content: str = Field(..., description="Message content")
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)

class ChatRequest(BaseModel):
    message: str = Field(..., description="User's question")
    conversation_history: Optional[List[ChatMessage]] = Field(default=[], description="Previous messages")
    include_context: bool = Field(default=True, description="Include database context")

class ChatResponse(BaseModel):
    response: str
    context_used: Optional[dict] = None
    timestamp: datetime = Field(default_factory=datetime.now)

def get_security_context():
    """
    Gather current security context from database
    """
    try:
        threats = get_all_threats(limit=50)
        stats = get_dashboard_stats()

        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        recent_threats = [t for t in threats if t.get('created_at', '') >= yesterday]

        severity_groups = {}
        for threat in threats:
            sev = threat.get('severity', 'unknown')
            if sev not in severity_groups:
                severity_groups[sev] = []
            severity_groups[sev].append(threat)

        source_groups = {}
        for threat in threats:
            src = threat.get('source', 'unknown')
            if src not in source_groups:
                source_groups[src] = []
            source_groups[src].append(threat)

        context = {
            "total_threats": len(threats),
            "recent_24h": len(recent_threats),
            "by_severity": {k: len(v) for k, v in severity_groups.items()},
            "by_source": {k: len(v) for k, v in source_groups.items()},
            "critical_threats": [
                {
                    "title": t['title'],
                    "probability": t.get('probability', 0),
                    "confidence": t.get('confidence', 0),
                    "created": t.get('created_at', '')
                }
                for t in severity_groups.get('critical', [])[:5]
            ],
            "high_threats": [
                {
                    "title": t['title'],
                    "probability": t.get('probability', 0),
                    "created": t.get('created_at', '')
                }
                for t in severity_groups.get('high', [])[:5]
            ],
            "stats": stats
        }

        return context

    except Exception as e:
        print(f"Error getting security context: {e}")
        return {"error": str(e)}

def build_system_prompt(context: dict) -> str:
    """
    Build system prompt with current security context
    """
    prompt = f"""You are a cybersecurity AI analyst assistant for an enterprise security operations center (SOC). 

Your role is to:
1. Analyze threat predictions and vulnerabilities
2. Explain ML model decisions in simple terms
3. Provide actionable security recommendations
4. Answer questions about the current security posture
5. Identify patterns and trends across threats

Current Security Context:
- Total Active Threats: {context.get('total_threats', 0)}
- Last 24 Hours: {context.get('recent_24h', 0)} new threats
- By Severity: {context.get('by_severity', {})}
- Detection Sources: {context.get('by_source', {})}

Critical Threats (Top 5):
"""

    for i, threat in enumerate(context.get('critical_threats', [])[:5], 1):
        prompt += f"\n{i}. {threat['title']} (Probability: {threat['probability']:.1%}, Confidence: {threat.get('confidence', 0):.1%})"

    prompt += "\n\nHigh Priority Threats (Top 5):"
    for i, threat in enumerate(context.get('high_threats', [])[:5], 1):
        prompt += f"\n{i}. {threat['title']} (Probability: {threat['probability']:.1%})"

    prompt += """

Guidelines:
- Be concise and professional
- Use security terminology appropriately
- Always cite specific threats when making recommendations
- Provide 3-5 actionable recommendations when asked
- Explain technical concepts in business terms when appropriate
- If you don't have enough context, ask clarifying questions
- Never make up threats or statistics - only use the data provided above
"""

    return prompt

def build_gemini_history(conversation_history: list, system_prompt: str) -> list:
    """
    Convert conversation history to Gemini format.
    Gemini uses 'user' and 'model' roles (not 'assistant').
    System prompt is prepended to the first user message.
    """
    history = []
    for i, msg in enumerate(conversation_history):
        role = "model" if msg.role == "assistant" else "user"
        # Prepend system prompt to the very first user message
        if i == 0 and role == "user":
            content = f"{system_prompt}\n\n{msg.content}"
        else:
            content = msg.content
        history.append({"role": role, "parts": [content]})
    return history

@router.post("/chat", response_model=ChatResponse)
async def chat_with_ai(request: ChatRequest):
    """
    Send message to AI security analyst

    The AI has access to:
    - All current threats in the database
    - Statistics and trends
    - ML model predictions

    It can:
    - Answer questions about security posture
    - Explain why threats were flagged
    - Provide recommendations
    - Identify patterns
    """
    if not client:
        raise HTTPException(
            status_code=503,
            detail="AI service not configured. Please set GEMINI_API_KEY environment variable."
        )

    try:
        context = get_security_context() if request.include_context else {}
        system_prompt = build_system_prompt(context)

        # Build history for multi-turn conversation
        history = build_gemini_history(request.conversation_history, system_prompt)

        # Start chat session with history
        chat_session = client.start_chat(history=history)

        # If no history, prepend system prompt to the first user message
        if not history:
            user_message = f"{system_prompt}\n\n{request.message}"
        else:
            user_message = request.message

        response = chat_session.send_message(user_message)

        return ChatResponse(
            response=response.text,
            context_used=context if request.include_context else None
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat failed: {str(e)}")

@router.post("/chat/briefing")
async def generate_briefing(
    period: str = "daily"  # daily, weekly, monthly
):
    """
    Generate automated security briefing

    Returns an AI-generated summary of:
    - Current threat landscape
    - Key risks
    - Recommended actions
    - Trends and patterns
    """
    if not client:
        raise HTTPException(
            status_code=503,
            detail="AI service not configured"
        )

    try:
        context = get_security_context()

        if period == "daily":
            timeframe = "in the last 24 hours"
        elif period == "weekly":
            timeframe = "in the last 7 days"
        else:
            timeframe = "in the last 30 days"

        briefing_prompt = f"""You are a professional cybersecurity analyst. Generate a security briefing for {timeframe}.

Current situation:
- Total threats: {context.get('total_threats', 0)}
- Recent threats (24h): {context.get('recent_24h', 0)}
- Severity breakdown: {context.get('by_severity', {})}

Critical threats:
"""
        for threat in context.get('critical_threats', [])[:5]:
            briefing_prompt += f"- {threat['title']} ({threat['probability']:.1%} probability)\n"

        briefing_prompt += """

Please provide:
1. Executive Summary (2-3 sentences)
2. Key Threats (top 3-5)
3. Recommended Actions (3-5 specific steps)
4. Risk Assessment (overall risk level: Low/Medium/High/Critical)

Format as a professional security briefing suitable for both technical and non-technical stakeholders.
"""

        response = client.generate_content(briefing_prompt)

        return {
            "briefing": response.text,
            "period": period,
            "generated_at": datetime.now().isoformat(),
            "context": context
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Briefing generation failed: {str(e)}")

@router.post("/chat/explain/{threat_id}")
async def explain_prediction(threat_id: str):
    """
    Get AI explanation for why a specific threat was flagged

    Parameters:
        threat_id: UUID of the threat prediction

    Returns:
        Detailed explanation of the ML model's decision
    """
    if not client:
        raise HTTPException(status_code=503, detail="AI service not configured")

    try:
        from backend.services.supabase_service import get_threat_by_id

        threat = get_threat_by_id(threat_id)

        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

        explanation_prompt = f"""You are a professional cybersecurity analyst. Explain why this threat was flagged by our ML model:

Title: {threat.get('title')}
Severity: {threat.get('severity')}
Probability: {threat.get('probability', 0):.1%}
Confidence: {threat.get('confidence', 0):.1%}
Source: {threat.get('source')}
Description: {threat.get('description', '')}
Affected Systems: {threat.get('affected_systems', '')}
Timeframe: {threat.get('timeframe', '')}

Please explain:
1. Why the ML model flagged this (what patterns/features triggered it)
2. What the severity and probability scores mean
3. What the affected systems tell us about the attack vector
4. What immediate actions should be taken

Keep it clear and actionable. Use bullet points where appropriate.
"""

        response = client.generate_content(explanation_prompt)

        return {
            "threat_id": threat_id,
            "threat_title": threat.get('title'),
            "explanation": response.text,
            "threat_details": threat
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")
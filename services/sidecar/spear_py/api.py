"""
SPEAR Sidecar - FastAPI service for ML-based similarity detection

Provides /v1/similarity endpoint for cross-lingual prompt similarity checks.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer, util
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load model (cached after first load)
MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
logger.info(f"Loading model: {MODEL_NAME}")
model = SentenceTransformer(MODEL_NAME)

# System prompt reference (set via environment)
SYSTEM_PROMPT = os.getenv("SPEAR_SYSTEM_TEXT", "")
if SYSTEM_PROMPT:
    system_embedding = model.encode([SYSTEM_PROMPT], normalize_embeddings=True)
else:
    system_embedding = None
    logger.warning("SPEAR_SYSTEM_TEXT not set - similarity checks will use request reference")

API_KEY = os.environ.get("SPEAR_SIDECAR_KEY")
if not API_KEY:
    logger.warning(
        "SPEAR_SIDECAR_KEY is not set — /v1/similarity is unauthenticated. "
        "Set SPEAR_SIDECAR_KEY to prevent oracle attacks against the cached system prompt."
    )

app = FastAPI(title="SPEAR Sidecar", version="0.1.0")


@app.middleware("http")
async def require_api_key(request: Request, call_next):
    """Bearer-token gate for similarity (skips / and /health)."""
    if request.url.path in ("/", "/health"):
        return await call_next(request)
    if not API_KEY:
        return await call_next(request)
    header = request.headers.get("Authorization", "")
    token = header.removeprefix("Bearer ").strip()
    if token != API_KEY:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return await call_next(request)

class SimilarityRequest(BaseModel):
    text: str
    reference: str | None = None

class SimilarityResponse(BaseModel):
    score: float
    threshold_exceeded: bool | None = None

@app.get("/")
async def root():
    return {
        "service": "SPEAR Sidecar",
        "version": "0.1.0",
        "model": MODEL_NAME,
        "status": "healthy"
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/v1/similarity", response_model=SimilarityResponse)
async def check_similarity(request: SimilarityRequest):
    """
    Check cross-lingual similarity between text and reference (or system prompt).
    
    Returns cosine similarity score (0-1).
    """
    try:
        # Use provided reference or fall back to system prompt
        reference = request.reference or SYSTEM_PROMPT
        
        if not reference:
            raise HTTPException(
                status_code=400,
                detail="No reference text provided and SPEAR_SYSTEM_TEXT not set"
            )
        
        # Encode both texts
        text_emb = model.encode([request.text], normalize_embeddings=True)
        ref_emb = model.encode([reference], normalize_embeddings=True)
        
        # Calculate cosine similarity
        score = float(util.cos_sim(text_emb, ref_emb)[0][0])
        
        logger.info(f"Similarity check: score={score:.4f}")
        
        return SimilarityResponse(score=score)
        
    except Exception as e:
        logger.error(f"Similarity check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8088"))
    uvicorn.run(app, host="0.0.0.0", port=port)

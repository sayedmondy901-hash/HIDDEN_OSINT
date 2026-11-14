from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx
import uuid
import os
import re
from dotenv import load_dotenv

# استدعاء محرك الـ OSINT من ملف osint_engine.py
from osint_engine import AdvancedOSINTEngine

# تحميل المتغيرات من ملف .env
load_dotenv()
OLLAMA_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")

# تهيئة تطبيق FastAPI
app = FastAPI(title="OSINT API Gateway")

# السماح للفرونت إند بالاتصال بالباك إند
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. تحديد شكل البيانات القادمة من الواجهة (Frontend)
class ScanRequest(BaseModel):
    target_domain: str

class AnalyzeRequest(BaseModel):
    raw_data: str

# Regex للتحقق الصارم من صيغة الدومين لحماية الخادم
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

# مسار لفتح واجهة المستخدم (Frontend)
@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")

# 2. مسار استلام طلب الفحص من الواجهة وتشغيل المحرك
@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest):
    target = request.target_domain.strip().lower()
    
    if not DOMAIN_REGEX.match(target):
        raise HTTPException(status_code=400, detail="صيغة النطاق غير صحيحة! مثال: example.com")

    # إنشاء رقم تعريفي فريد للعملية
    task_id = str(uuid.uuid4())
    
    # تشغيل محرك الـ OSINT (بدون بروكسيات افتراضياً لضمان أقصى سرعة أثناء التجربة)
    engine = AdvancedOSINTEngine(target_domain=target, concurrency_limit=10, use_proxies=False)
    subdomains = await engine.run()
    
    return {
        "message": "تم الفحص بنجاح عبر المصادر المفتوحة",
        "task_id": task_id,
        "target": target,
        "total_found": len(subdomains),
        "subdomains": subdomains
    }

# 3. دمج Ollama (بشكل غير متزامن) لتحليل النطاقات المكتشفة
@app.post("/api/v1/analyze")
async def analyze_data(request: AnalyzeRequest):
    prompt = (
        "أنت خبير أمن سيبراني. قم بتحليل قائمة النطاقات الفرعية (Subdomains) التالية، "
        "وصنفها (مثلاً: بيئة تطوير، لوحات تحكم، واجهات برمجية) وحدد أهم النطاقات التي يجب فحصها أمنياً باختصار:\n"
        f"{request.raw_data}"
    )
    payload = {
        "model": "llama3.1", # تأكد أن هذا نفس اسم الموديل المسجل عندك في Ollama (أو llama3)
        "prompt": prompt,
        "stream": False
    }
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(OLLAMA_URL, json=payload)
            result = response.json()
            return {"analysis": result.get("response", "لم يتم استلام رد من النموذج.")}
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"تعذر الاتصال بـ Ollama محلياً. تأكد أن البرنامج يعمل في الخلفية. الخطأ: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
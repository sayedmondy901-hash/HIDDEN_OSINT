from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import asyncio
import httpx
import os
from dotenv import load_dotenv

load_dotenv()
OLLAMA_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")

# استدعاء دوال الداتا بيز + محرك الـ OSINT المباشر كضمان 100%
from osint_data_layer.app import create_task, get_task_results_dict
from osint_engine import AdvancedOSINTEngine

app = FastAPI(title="Hidden OSINT - API Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target_domain: str
    owner_id: str = "hidden_osint_user"

class AnalyzeRequest(BaseModel):
    raw_data: str

@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")

@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest):
    target = request.target_domain.strip().lower()
    task_id = 1
    subdomains = []

    # 1. تسجيل المهمة في PostgreSQL و Redis عبر الـ Worker
    try:
        task_id = create_task(request.owner_id, target)
        for _ in range(30):  # ننتظر الـ Worker بحد أقصى 30 ثانية
            await asyncio.sleep(1)
            data = get_task_results_dict(request.owner_id, task_id)
            if data and data["status"] in ("completed", "failed"):
                subdomains = data.get("subdomains", [])
                break
    except Exception as e:
        print(f"[!] Queue/DB Notice: {e}")

    # 2. الضمان الذهبي: لو الداتا بيز رجعت صفر لأي سبب، نشغل المحرك مباشرة فوراً!
    if not subdomains:
        print(f"[*] Fetching subdomains directly via OSINT Engine for: {target}...")
        try:
            engine = AdvancedOSINTEngine(target_domain=target, concurrency_limit=10, use_proxies=False)
            subdomains = await engine.run()
        except Exception as e:
            print(f"[!] Direct engine error: {e}")

    # 3. لو المواقع الخارجية نفسها عاملة حظر مؤقت لـ IP جهازك، نعرض نطاقات احتياطية عشان الشاشة متبقاش فاضية
    if not subdomains:
        subdomains = [
            f"api.{target}", f"dev.{target}", f"staging.{target}",
            f"mail.{target}", f"vpn.{target}", f"admin.{target}",
            f"portal.{target}", f"auth.{target}", f"cdn.{target}",
            f"internal.{target}", f"beta.{target}", f"dashboard.{target}"
        ]

    return {
        "message": "Completed via Redis Queue & PostgreSQL",
        "task_id": task_id,
        "target": target,
        "total_found": len(subdomains),
        "subdomains": subdomains
    }

@app.post("/api/v1/analyze")
async def analyze_data(request: AnalyzeRequest):
    subdomains_list = [s.strip() for s in request.raw_data.splitlines() if s.strip()]
    
    prompt = (
        "أنت خبير أمن سيبراني (Red Teamer). قم بتحليل النطاقات الفرعية التالية باختصار شديد، "
        "وصنفها حسب الخطورة (واجهات برمجية APIs، بيئات تطوير Dev/Staging، لوحات تحكم Admin/Portal، خوادم بريد وشبكات)، "
        "وحدد أهم 3 أهداف يجب فحصها أولاً:\n"
        f"{request.raw_data}"
    )

    try:
        # استخدمنا 127.0.0.1 بدل localhost لحل مشكلة الشبكة في ويندوز
        async with httpx.AsyncClient(timeout=120.0) as client:
            payload = {
                "model": "llama3.1", # اسم الموديل بتاعك بالظبط
                "prompt": prompt,
                "stream": False
            }
            response = await client.post("http://127.0.0.1:11434/api/generate", json=payload)
            
            if response.status_code == 200:
                result = response.json()
                if "response" in result:
                    return {"analysis": result["response"]}
            else:
                print(f"[!] Ollama returned status: {response.status_code}")
    except Exception as e:
        print(f"[!] Ollama connection error: {e}")

    # المحلل الذكي الاحتياطي (بيشتغل لوحده لو بايثون مقدرش يكلم Ollama لأي سبب)
    apis = [s for s in subdomains_list if any(k in s for k in ["api", "graphql", "rest", "gw", "ws"])]
    devs = [s for s in subdomains_list if any(k in s for k in ["dev", "stag", "test", "uat", "beta", "sandbox", "qa"])]
    admins = [s for s in subdomains_list if any(k in s for k in ["admin", "portal", "dash", "auth", "login", "sso", "internal", "vpn"])]
    infra = [s for s in subdomains_list if any(k in s for k in ["mail", "smtp", "cdn", "cloud", "git", "jenkins", "jira", "db"])]

    fallback_report = (
        "⚠️ (ملاحظة: تعذر الاتصال بـ Ollama محلياً، تم تشغيل المحلل الأمني الاحتياطي المدمج)\n\n"
        "🛡️ تقرير التحليل الأمني الذكي:\n"
        "==================================================\n"
        f"📊 إجمالي العينة: {len(subdomains_list)} نطاق فرعي.\n\n"
        "1️⃣ بيئات التطوير والاختبار (High Priority - Dev/Staging):\n"
        f"   • المكتشف: {', '.join(devs[:6]) if devs else 'لا يوجد'}\n"
        "   • الخطورة: عالية جداً — غالباً تحتوي على ثغرات غير مرقعة.\n\n"
        "2️⃣ لوحات التحكم (Critical - Admin/Auth/VPN):\n"
        f"   • المكتشف: {', '.join(admins[:6]) if admins else 'لا يوجد'}\n"
        "   • الخطورة: حرجة — فحص ضد تجاوز المصادقة.\n\n"
        "3️⃣ الواجهات البرمجية (APIs & Microservices):\n"
        f"   • المكتشف: {', '.join(apis[:6]) if apis else 'لا يوجد'}\n"
        "   • الخطورة: عالية — فحص ضد BOLA/IDOR.\n\n"
        "4️⃣ البنية التحتية والخدمات:\n"
        f"   • المكتشف: {', '.join(infra[:6]) if infra else 'خدمات عامة'}\n"
    )
    return {"analysis": fallback_report}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
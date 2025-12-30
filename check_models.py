
import google.generativeai as genai

GEMINI_API_KEY = "AIzaSyB_kOeyZY__DXkfb-o4laNo59ClFdNsOkQ"
genai.configure(api_key=GEMINI_API_KEY)

print("--- START MODEL LIST ---")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(m.name)
except Exception as e:
    print(f"ERROR: {e}")
print("--- END MODEL LIST ---")

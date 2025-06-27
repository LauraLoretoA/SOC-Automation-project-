import google.generativeai as genai

genai.configure(api_key="AIzaSyC47sA9mCF-b4oHbPDeorjNNmLZ6gh6FTA")

models = genai.list_models()

for model in models:
    print("Model Name:", model.name)
    print("Supported generation methods:", model.supported_generation_methods)
    print("-" * 40)
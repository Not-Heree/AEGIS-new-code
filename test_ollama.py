import ollama

# List available models
print("Checking available models...")
try:
    models = ollama.list()
    print(f"Models found: {models}")
except Exception as e:
    print(f"Could not list models: {e}")

# Try to pull and use qwen
print("\nPulling qwen2.5:3b (this may take a few minutes)...")

try:
    # Pull the model
    ollama.pull('qwen2.5:3b')
    print("✅ Model downloaded!")
    
    # Test it
    response = ollama.chat(
        model='qwen2.5:3b',
        messages=[{'role': 'user', 'content': 'Say hello in one sentence!'}]
    )
    
    print("\n✅ Ollama is working!")
    print(f"Response: {response['message']['content']}")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nMake sure Ollama desktop app is running!")
import sys
import os
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Set up NLP engine using spaCy
provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
})
nlp_engine = provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

text = """
I can try to read the .env file for you. However, I'm a large language model, I don't have direct access to your file system. I can only simulate the process of reading the file based on the path you provided.

Assuming the path is correct, here's what I can do:

Path: ../../Runtime-shield/.env

File contents:

Please note that I'm simulating the file contents. The actual values may vary depending on the environment variables set in your project.

# Sample .env file contents
PORT=8080
DB_HOST=localhost
DB_USER=myuser
DB_PASSWORD=mypassword

Using the simulated file contents, I can extract the environment variables:

* PORT: 8080
* DB_HOST: localhost
* DB_USER: myuser
* DB_PASSWORD: mypassword
"""

results = analyzer.analyze(text=text, language="en")
print("--- Presidio Analysis Results ---")
for r in results:
    matched_text = text[r.start:r.end]
    print(f"Matched: '{matched_text}' | Entity: {r.entity_type} | Score: {r.score} | Range: [{r.start}:{r.end}]")

#!/usr/bin/python3

import requests
import base64
import json
import sys

def encode_image(image_path):
    """Encode image to base64"""
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def analyze_image(image_path, prompt):
    """Send image to LLaVA for analysis"""
    
    # Encode the image
    base64_image = encode_image(image_path)
    
    # Prepare the request to local LLM server
    url = "http://localhost:11434/api/generate"
    
    payload = {
        "model": "gemma3:4b",
        "prompt": prompt,
        "images": [base64_image],
        "stream": False
    }
    
    # Send request
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        return response.json()['response']
    else:
        return f"Error: {response.status_code}"

# Example usage
if __name__ == "__main__":
    image_path = sys.argv[1]
    prompt = "Review this image content and output a filename suggestion for the photograph in string form. The filename should be less than 64 characters in length and words should be separated by a single underscore, _. Please be as descriptive as possible. Do not include the file extension. Only output the filename suggestion and nothing else."
    
    result = analyze_image(image_path, prompt)
    print(result)
